# finance-api — Finance PWA backend

Общие правила инфраструктуры — в корневом `/home/alvik/AGENTS.md`.

## OCR чеков и QR (proverkacheka)
- `POST /api/instances/:id/fetch-receipt` (принимает `qr_string`, `cookies`), `GET /api/yandex/auth-url`, `POST /api/yandex/code`, `GET /api/yandex/session`, `POST /api/pkc-proxy` (прокси к proverkacheka.com с куками из заголовка `X-PKC-Cookies`).
- **Проблема кук**: API proverkacheka требует `sessionid2` без `fakesign` — placeholder подписывается только в браузере с активной Яндекс-сессией. Вариант 1 (июнь 2026): в Dockerfile установлены Chrome 149 + Xvfb (`node:22-bookworm-slim`), `entrypoint.sh` поднимает `Xvfb :99` и Chrome `--remote-debugging-port=9222 --user-data-dir=/app/chrome-profile`; модуль `src/pkc-browser.js` (`isLoggedIn`, `getCookiesFromBrowser`, `doYandexLogin`, `refreshSessionIfNeeded`); эндпоинты `/api/pkc-browser/{status,init,complete,refresh}`; контейнер `network_mode: "host"`. **Требуется ручной логин в Яндекс через Chrome контейнера** (порт 9222) для генерации валидных кук; далее автообновление через refresh.
- Яндекс OAuth: Client ID `0f023acb2cc34a1a86a395e1db4306f5`, redirect `https://oauth.yandex.ru/verification_code`, права только «Яндекс.Директ» (нет login:info). Секрет в `.env`.
