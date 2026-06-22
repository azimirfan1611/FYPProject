FROM alpine:3.18

WORKDIR /

COPY credentials.txt .

EXPOSE 9001

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=3 \
  CMD test -f /credentials.txt && echo "OK" || exit 1

CMD ["sleep", "infinity"]
