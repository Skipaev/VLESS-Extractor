# VLESS-Extractor

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Простой и мощный инструмент на Python для извлечения чистых VLESS-ссылок из подписок.

> [!TIP]
> [Онлайн извлечение VLESS](https://vlessextractor.mooo.com/)

## Русский / Russian

### Для чего нужен
Получает подписку по URL  
Отправляет HWID и данные устройства (как это делает клиент Throne)  
Полностью маскируется под Throne (User-Agent, заголовки x-hwid, x-ver-os и т.д.)  
Декодирует base64, парсит sing-box JSON, конвертирует vmess → vless  
Выдаёт чистые vless:// ссылки, готовые для импорта в любой клиент (Nekobox, v2rayNG, Hiddify, Sing-box и др.)  
Показывает Subscription-Userinfo (трафик, expire, total)

### Основные возможности
Максимальная совместимость с механикой Throne по запросу подписки  
Поддержка кастомных HWID-параметров (формат: hwid=xxx,os=Win)  
Игнор SSL-ошибок (опционально)  
Парсинг sing-box outbounds (vless + vmess)  
Удобное меню: показать полные ссылки, сохранить в файл, скопировать в буфер, сохранить как base64  
Обработка Profile-Title и Subscription-Userinfo из заголовков

### Установка и запуск

1. Установите зависимости:
   pip install requests pyperclip

2. Запустите скрипт:
   python vless_extractor.py

3. Введите URL подписки → получите чистые VLESS-ссылки

### Важно
Инструмент создан исключительно в образовательных и исследовательских целях.  
Используйте только те подписки, которые вам официально разрешены.  
Автор не несёт ответственности за использование в нарушение условий сервисов.

### Авторы
Основная логика и код: Claude Opus 4.5 (Anthropic)      
Значительная помощь в анализе исходного кода Throne и доработке: Grok (xAI) 

Проект создан в январе 2026 года.

---

## English

### What is this
A simple and powerful Python tool to extract clean VLESS links from subscription URLs.

### Purpose
Fetches subscription from URL  
Sends HWID and device info (exactly like Throne client does)  
Fully mimics Throne behavior (User-Agent, x-hwid / x-ver-os headers, etc.)  
Decodes base64, parses sing-box JSON, converts vmess → vless  
Outputs clean vless:// links ready for any client (Nekobox, v2rayNG, Hiddify, Sing-box, etc.)  
Displays Subscription-Userinfo (traffic used, total, expire)

### Features
Maximum compatibility with Throne subscription request logic  
Custom HWID parameters support (format: hwid=xxx,os=Win)  
Optional SSL certificate verification ignore  
sing-box outbound parsing (vless + vmess)  
Convenient menu: show full links, save to file, copy to clipboard, save as base64  
Handles Profile-Title and Subscription-Userinfo headers

### Installation & Usage

1. Install dependencies:
   pip install requests pyperclip

2. Run the script:
   python vless_extractor.py

3. Enter subscription URL → get clean VLESS links

### Important
This tool is created for educational and research purposes only.  
Use only with subscriptions you are officially allowed to access.  
The author is not responsible for any misuse or violation of third-party service terms.

### Authors
Core logic and code: Claude Opus 4.5 (Anthropic)  
Major assistance in Throne source code analysis and improvements: Grok (xAI)

Project created in January 2026.
