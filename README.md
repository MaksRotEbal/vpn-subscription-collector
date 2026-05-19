# VPN Subscription Collector

Автообновляемые подписки из открытых источников: **БС (WL)**, **ЧС (BL)** и **ALL**. Перед добавлением в подписку каждый сервер проходит **проверку доступности** — TCP-подключение к `host:port` (таймаут ~4 с), без полноценного VPN-туннеля.

## Файлы (после push на GitHub)

Замените `USER` и `REPO` на свой логин и репозиторий:

| Подписка | URL (raw) |
|----------|-----------|
| WL (БС, до 100) | `https://raw.githubusercontent.com/USER/REPO/main/output/MaksRotEbal_WL.txt` |
| BL (ЧС, до 100) | `https://raw.githubusercontent.com/USER/REPO/main/output/MaksRotEbal_BL.txt` |
| ALL (до 200) | `https://raw.githubusercontent.com/USER/REPO/main/output/MaksRotEbal_ALL.txt` |

Имена узлов в клиенте — **только страна** (например `Netherlands` или `🇳🇱 Netherlands`).

## Клиенты

### v2rayNG (Android)
Подписки → `+` → «Импорт из буфера/URL» → вставьте raw-ссылку на `MaksRotEbal_*.txt` → обновить.

### Hiddify
Главная → «Добавить профиль» → «Подписка» → URL одного из файлов выше → сохранить.

### Streisand (iOS)
`+` → «Subscribe» / подписка по URL → вставьте raw-ссылку → обновить список.

### v2rayN (Windows)
Подписка → настройки группы → URL подписки → обновить подписку.

## Локальный запуск

```bash
pip install -r requirements.txt
python scripts/collect.py
python scripts/collect.py --offline   # без сети и без ping (тест)
pytest
```

Источники и лимиты: `config/sources.yaml`, классификация БС/ЧС: `config/classification.yaml`.

> Только легальные публичные источники. Ответственность за использование — на вас.
