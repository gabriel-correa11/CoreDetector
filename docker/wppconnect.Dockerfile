FROM node:22-alpine AS builder

RUN apk add --no-cache git python3 make g++

WORKDIR /usr/src/wpp-server

RUN git clone --depth 1 https://github.com/wppconnect-team/wppconnect-server.git . \
    && npm ci \
    && npm run build

FROM node:22-alpine

RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    udev \
    xvfb

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /usr/src/wpp-server

COPY --from=builder /usr/src/wpp-server/dist ./dist
COPY --from=builder /usr/src/wpp-server/node_modules ./node_modules
COPY --from=builder /usr/src/wpp-server/package.json ./package.json

RUN mkdir -p tokens

EXPOSE 21465

CMD ["node", "dist/server.js"]
