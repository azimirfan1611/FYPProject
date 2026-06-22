FROM alpine:3.18

RUN apk add --no-cache dnsmasq

EXPOSE 53/udp 53/tcp

COPY dnsmasq.conf /etc/dnsmasq.conf

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD test -f /etc/dnsmasq.conf || exit 1

CMD ["dnsmasq", "-k", "-C", "/etc/dnsmasq.conf"]
