FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    xdg-utils \
    xvfb \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable
ENV PUPPETEER_CACHE_DIR=/app/.cache/puppeteer
ENV CHROME_PROFILE_DIR=/app/chrome-profile

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --production

COPY . .

RUN chmod +x /app/scripts/entrypoint.sh

RUN mkdir -p /app/chrome-profile /app/.cache/puppeteer && \
    chown -R node:node /app/chrome-profile /app/.cache/puppeteer /app/scripts/entrypoint.sh

USER node

EXPOSE 3000

CMD ["/app/scripts/entrypoint.sh"]
