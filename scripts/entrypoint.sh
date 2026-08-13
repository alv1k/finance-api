#!/bin/bash
set -e

# Start the API
echo "[entrypoint] Starting API..."
node src/index.js
