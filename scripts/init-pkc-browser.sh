#!/bin/bash
set -e

echo "=== PKC Browser Init ==="
echo "This script initializes Chrome profile for proverkacheka.com authentication"
echo ""

cd /home/alvik/finance-api

if [ ! -d chrome-profile ]; then
  mkdir -p chrome-profile
  echo "Created chrome-profile directory"
fi

if [ ! -d .cache/puppeteer ]; then
  mkdir -p .cache/puppeteer
  echo "Created .cache/puppeteer directory"
fi

echo ""
echo "Building Docker image with Chrome..."
docker compose build api

echo ""
echo "Starting container..."
docker compose up -d

echo ""
echo "Waiting for API to be ready..."
sleep 5

echo ""
echo "Initiating browser login..."
curl -s -X POST http://localhost:3000/api/pkc-browser/init \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat /home/alvik/finance-api/.jwt_token 2>/dev/null || echo '')" | jq .
