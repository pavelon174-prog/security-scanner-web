# app/main.py
import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from .scanner.core import SecurityScanner
from .scanner.report_generator import ReportGenerator

app = FastAPI(title="Security Scanner", version="1.0.1")

# Настройка CORS.
# allow_origins=["*"] несовместим с allow_credentials=True (браузеры это
# отклоняют/игнорируют) — этому инструменту креды не нужны, поэтому
# credentials выключены. Если появится авторизация — перечислите
# конкретные origin'ы вместо "*".
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Настройка статики и шаблонов
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# report_id — это timestamp вида 20260830_005508, генерируемый ReportGenerator.
# Жёсткая валидация формата закрывает path traversal в /api/report/{report_id}.
REPORT_ID_RE = re.compile(r"^\d{8}_\d{6}$")

# Состояние сканирования
scan_status: Dict[str, Any] = {
    "is_running": False,
    "progress": 0,
    "status": "idle",
    "result": None,
}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Главная страница"""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """Страница сканирования"""
    return templates.TemplateResponse("scan.html", {"request": request})


@app.post("/api/scan/start")
async def start_scan(background_tasks: BackgroundTasks):
    """Запуск сканирования"""
    if scan_status["is_running"]:
        return JSONResponse(
            status_code=400,
            content={"error": "Сканирование уже выполняется"},
        )

    scan_status["is_running"] = True
    scan_status["progress"] = 0
    scan_status["status"] = "running"
    scan_status["result"] = None
    scan_status.pop("error", None)

    background_tasks.add_task(run_scan)

    return JSONResponse(content={"status": "started"})


@app.get("/api/scan/status")
async def get_scan_status():
    """Получение статуса сканирования"""
    return JSONResponse(content=scan_status)


@app.get("/api/scan/result")
async def get_scan_result():
    """Получение результатов сканирования"""
    if scan_status["result"]:
        return JSONResponse(content=scan_status["result"])
    return JSONResponse(content={"error": "Результатов нет"}, status_code=404)


@app.get("/api/reports")
async def list_reports():
    """История сгенерированных отчётов (раньше нигде не была доступна)"""
    reports = []
    for path in sorted(REPORTS_DIR.glob("security_report_*.html"), reverse=True):
        report_id = path.stem.replace("security_report_", "")
        if REPORT_ID_RE.match(report_id):
            reports.append({
                "report_id": report_id,
                "created": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
            })
    return JSONResponse(content={"reports": reports})


@app.get("/api/report/{report_id}")
async def get_report(
    report_id: str,
    format: str = Query(default="html", pattern="^(html|pdf|json)$"),
):
    """Получение отчета в формате html / pdf / json"""
    if not REPORT_ID_RE.match(report_id):
        raise HTTPException(status_code=400, detail="Некорректный идентификатор отчета")

    report_path = REPORTS_DIR / f"security_report_{report_id}.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Отчет не найден")

    if format == "html":
        return FileResponse(
            report_path,
            media_type="text/html",
            filename=f"security_report_{report_id}.html",
        )

    if format == "json":
        # Отдаём последний известный результат, если он совпадает с этим report_id,
        # иначе — минимальную заглушку (сырые данные сканирования не хранятся
        # постатейно на диске, только готовый HTML).
        if scan_status.get("result") and scan_status["result"].get("report_id") == report_id:
            payload = scan_status["result"]
        else:
            payload = {"report_id": report_id, "note": "Подробные JSON-данные доступны только для последнего скана"}
        data = json.dumps(payload, ensure_ascii=False, indent=2)
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="report_{report_id}.json"'},
        )

    if format == "pdf":
        try:
            from weasyprint import HTML  # опциональная зависимость
        except ImportError:
            raise HTTPException(
                status_code=501,
                detail="PDF-экспорт требует пакет 'weasyprint' (pip install weasyprint)",
            )
        pdf_bytes = HTML(filename=str(report_path)).write_pdf()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="security_report_{report_id}.pdf"'},
        )

    # недостижимо благодаря Query(pattern=...), но на всякий случай
    raise HTTPException(status_code=400, detail="Неизвестный формат")


async def run_scan():
    """Фоновое выполнение сканирования"""
    try:
        scanner = SecurityScanner()

        for i in range(1, 101, 10):
            scan_status["progress"] = i
            await asyncio.sleep(0.3)

        result = scanner.run_full_scan()

        generator = ReportGenerator(result)
        report_path = generator.generate_html_report()

        scan_status["result"] = {
            "total": result.total_vulnerabilities,
            "severities": result.severity_breakdown,
            "hostname": result.hostname,
            "os": result.os_info.get("os", "Unknown"),
            "duration": result.scan_duration,
            "report_path": str(report_path),
            "report_id": report_path.stem.replace("security_report_", ""),
            "vulnerabilities": [
                {
                    "severity": v.severity,
                    "title": v.title,
                    "description": v.description,
                    "remediation": v.remediation,
                    "category": v.category,
                    "component": v.affected_component,
                    "cve": v.cve_id,
                    "cvss": v.cvss_score,
                }
                for v in result.vulnerabilities
            ],
            "recommendations": result.recommendations,
            "system_health": result.system_health,
        }

        scan_status["status"] = "completed"
        scan_status["progress"] = 100

    except Exception as e:
        scan_status["status"] = "error"
        scan_status["error"] = str(e)
    finally:
        scan_status["is_running"] = False


@app.get("/api/health")
async def health_check():
    """Проверка здоровья сервера"""
    return JSONResponse(content={"status": "healthy", "timestamp": datetime.now().isoformat()})
