FROM nginx:1.27-alpine

RUN apk add --no-cache openssl
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout /etc/nginx/ssl/lab.key \
      -out /etc/nginx/ssl/lab.crt \
      -subj "/CN=autopentest-lab.local/O=AutoPenTest Lab/OU=Validation"

COPY nginx.conf /etc/nginx/nginx.conf

CMD ["nginx", "-g", "daemon off;"]
