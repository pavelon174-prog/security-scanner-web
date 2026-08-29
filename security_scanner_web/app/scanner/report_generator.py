from datetime import datetime
from pathlib import Path
from html import escape


class ReportGenerator:
    def __init__(self, scan_result):
        self.result = scan_result
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_html_report(self, output_file: str = None) -> Path:
        """Генерация HTML-отчета. Возвращает путь к файлу.
        Имя файла всегда security_report_<timestamp>.html — это имя
        используется как report_id при последующем скачивании."""
        if not output_file:
            reports_dir = Path(__file__).resolve().parent.parent.parent / "reports"
            reports_dir.mkdir(exist_ok=True)
            output_file = reports_dir / f"security_report_{self.timestamp}.html"
        else:
            output_file = Path(output_file)

        html = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>Отчет безопасности</title>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; background: #f0f2f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 16px; }}
                h1 {{ color: #1a1a2e; }}
                .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }}
                .stat {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
                .stat .number {{ font-size: 28px; font-weight: bold; }}
                .vuln {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #6c757d; }}
                .vuln.critical {{ border-left-color: #dc3545; }}
                .vuln.high {{ border-left-color: #fd7e14; }}
                .vuln.medium {{ border-left-color: #ffc107; }}
                .vuln.low {{ border-left-color: #28a745; }}
                .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 12px; }}
                .badge-critical {{ background: #dc3545; color: white; }}
                .badge-high {{ background: #fd7e14; color: white; }}
                .badge-medium {{ background: #ffc107; color: black; }}
                .badge-low {{ background: #28a745; color: white; }}
                .remediation {{ background: #e9ecef; padding: 10px; border-radius: 6px; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ Отчет по безопасности системы</h1>
                <p>Сгенерирован: {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</p>
                <p>Хост: {escape(self.result.hostname)} | ОС: {escape(self.result.os_info.get('os', 'Unknown'))}</p>

                <div class="stats">
                    <div class="stat"><div class="number" style="color:#dc3545;">{self.result.total_vulnerabilities}</div><div>Всего</div></div>
                    <div class="stat"><div class="number" style="color:#dc3545;">{self.result.severity_breakdown.get('CRITICAL', 0)}</div><div>Критических</div></div>
                    <div class="stat"><div class="number" style="color:#fd7e14;">{self.result.severity_breakdown.get('HIGH', 0)}</div><div>Высоких</div></div>
                    <div class="stat"><div class="number" style="color:#ffc107;">{self.result.severity_breakdown.get('MEDIUM', 0)}</div><div>Средних</div></div>
                    <div class="stat"><div class="number" style="color:#28a745;">{self.result.severity_breakdown.get('LOW', 0)}</div><div>Низких</div></div>
                </div>

                <h2>🔍 Детальный список уязвимостей</h2>
                {self._generate_vulnerabilities_html()}

                <h2>📋 Рекомендации</h2>
                <ul>
                    {self._generate_recommendations_html()}
                </ul>

                <p style="margin-top:30px; color:#6c757d;">Сканирование завершено за {self.result.scan_duration:.2f} секунд</p>
            </div>
        </body>
        </html>
        """

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        return output_file

    def _generate_vulnerabilities_html(self) -> str:
        if not self.result.vulnerabilities:
            return '<p style="color:#28a745;">✅ Уязвимостей не обнаружено</p>'
        html = ""
        for vuln in self.result.vulnerabilities:
            severity_class = vuln.severity.lower()
            html += f"""
            <div class="vuln {severity_class}">
                <div style="display:flex; justify-content:space-between;">
                    <strong>{escape(vuln.title)}</strong>
                    <span class="badge badge-{severity_class}">{escape(vuln.severity)}</span>
                </div>
                <p>{escape(vuln.description)}</p>
                <p style="font-size:14px; color:#6c757d;">Компонент: {escape(vuln.affected_component)} | Категория: {escape(vuln.category)}</p>
                <div class="remediation"><strong>🔧 Исправление:</strong> {escape(vuln.remediation)}</div>
            </div>
            """
        return html

    def _generate_recommendations_html(self) -> str:
        if not self.result.recommendations:
            return "<li>Критичных рекомендаций нет</li>"
        return "".join(f"<li>{escape(rec)}</li>" for rec in self.result.recommendations)
