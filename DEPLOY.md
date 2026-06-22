# Деплой на VPS (91.132.161.112)

## 1. Скопировать файлы на сервер
```bash
scp -r server/ user@91.132.161.112:~/finance-api/
scp Финансовые_записи_2026-04-08.xlsx user@91.132.161.112:~/finance-api/
```

## 2. На сервере: запустить контейнеры
```bash
cd ~/finance-api
docker compose up -d
```

## 3. Установить зависимости и запустить миграцию + импорт
```bash
docker compose exec api npm run migrate
docker compose exec api node src/import-xlsx.js /data/file.xlsx
```

Или без Docker (для импорта локально):
```bash
cd ~/finance-api
npm install
DB_HOST=localhost npm run migrate
DB_HOST=localhost node src/import-xlsx.js ./Финансовые_записи_2026-04-08.xlsx
```

## 4. Настроить nginx
```bash
sudo cp nginx-finance-api.conf /etc/nginx/sites-enabled/finance-api
sudo nginx -t
sudo systemctl reload nginx
```

## 5. Проверить
```bash
curl http://91.132.161.112:64278/api/health
curl http://91.132.161.112:64278/api/categories
```
