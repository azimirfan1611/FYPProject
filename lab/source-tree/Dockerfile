FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* .

RUN npm ci --production 2>/dev/null || npm install --production

COPY vulnerable-code/ /app/vulnerable-code/

EXPOSE 9000

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD test -d /app/vulnerable-code && echo "OK" || exit 1

CMD ["tail", "-f", "/dev/null"]
