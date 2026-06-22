FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git npm && rm -rf /var/lib/apt/lists/*

COPY vulnerable-code/ /app/vulnerable-code/
COPY package.json /app/

RUN npm install

EXPOSE 9000

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD test -d /app/vulnerable-code && echo "OK" || exit 1

CMD ["tail", "-f", "/dev/null"]
