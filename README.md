[README.md](https://github.com/user-attachments/files/31603556/README.md)# 🛡️ Security Scanner Web

Веб-инструмент для быстрой проверки безопасности системы: находит уязвимости, оценивает их критичность и формирует наглядный отчёт с рекомендациями по устранению.

Построен на **FastAPI** + лёгком фронтенде на Tailwind CSS, без внешних БД — запускается локально в пару команд.

---

## ✨ Возможности

- 🔍 **Проверка системы в реальном времени** — версия Python, версия OpenSSL, состояние брандмауэра Windows, открытые опасные порты, устаревшие службы (Telnet и др.)
- 📊 **Наглядная панель результатов** — уязвимости с разбивкой по критичности (Critical / High / Medium / Low)
- 📄 **Экспорт отчётов** — HTML, PDF и JSON
- 🧩 **Рекомендации по hardening** — конкретные шаги для устранения каждой найденной проблемы
- ⚡ **Асинхронное сканирование** — прогресс-бар и статус в реальном времени через REST API


---

## 🚀 Быстрый старт

```bash
# 1. Клонировать репозиторий
git clone https://github.com/pavelon174-prog/security-scanner-web.git
cd security-scanner-web

# 2. Создать и активировать виртуальное окружение
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Установить зависимости
pip install -r requirements.txt

# 4. Запустить сервер
python run.py
```

Открой в браузере:
- **http://localhost:8000** — главная страница
- **http://localhost:8000/scan** — запуск сканирования

> 💡 Экспорт в PDF требует пакет `weasyprint`. Если он не устанавливается на твоей ОС — просто закомментируй строку в `requirements.txt`, остальной функционал (HTML/JSON) будет работать без него.

---

## 🗂️ Структура проекта

```
security-scanner-web/
├── app/
│   ├── main.py               # FastAPI-приложение и роуты
│   ├── scanner/
│   │   ├── core.py           # Логика сканирования
│   │   └── report_generator.py  # Генерация HTML-отчётов
│   ├── templates/            # HTML-шаблоны (Jinja2)
│   └── static/                # CSS/JS
├── reports/                   # Сгенерированные отчёты
├── requirements.txt
└── run.py                     # Точка входа
```

---

## 🛠️ Технологии

- **Backend:** FastAPI, Uvicorn, psutil
- **Frontend:** Tailwind CSS, Font Awesome
- **Отчёты:** Jinja2, WeasyPrint (PDF)

---

## 📋 API

| Метод | Эндпоинт | Описание |
|---|---|---|
| `GET` | `/` | Главная страница |
| `GET` | `/scan` | Страница сканирования |
| `POST` | `/api/scan/start` | Запуск сканирования |
| `GET` | `/api/scan/status` | Статус сканирования |
| `GET` | `/api/scan/result` | Результат последнего скана |
| `GET` | `/api/reports` | История отчётов |
| `GET` | `/api/report/{id}?format=html\|pdf\|json` | Скачать отчёт |
| `GET` | `/api/health` | Проверка работоспособности сервера |

---

## 📝 Лицензия

Свободно используй и дорабатывай под свои задачи.

