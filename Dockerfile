FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-pil \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --production

COPY . .

RUN chmod +x /app/scripts/entrypoint.sh

USER node

EXPOSE 3000

CMD ["/app/scripts/entrypoint.sh"]
