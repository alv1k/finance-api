#!/bin/bash
set -e

# Start Xvfb for headful Chrome support
Xvfb :99 -screen 0 1280x1024x24 &
export DISPLAY=:99

# Start Chrome with remote debugging for manual login (if profile doesn't exist)
if [ ! -d /app/chrome-profile/Default ]; then
  echo "[entrypoint] No Chrome profile found, starting Chrome with remote debugging..."
  google-chrome-stable \
    --no-sandbox \
    --disable-setuid-sandbox \
    --disable-dev-shm-usage \
    --disable-gpu \
    --remote-debugging-port=9222 \
    --user-data-dir=/app/chrome-profile \
    --no-first-run \
    --no-default-browser-check \
    "https://proverkacheka.com" &
  echo "[entrypoint] Chrome started with remote debugging on port 9222"
  echo "[entrypoint] Open http://localhost:9222 to control the browser"
fi

# Start the API
echo "[entrypoint] Starting API..."
node src/index.js
