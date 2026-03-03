FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git perl libnet-ssleay-perl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# Install Python deps from both pentester and dashboard requirements
COPY pentester/requirements.txt /tmp/pentest_req.txt
COPY dashboard/requirements.txt /tmp/dash_req.txt
RUN pip install --no-cache-dir -r /tmp/pentest_req.txt -r /tmp/dash_req.txt sqlmap

# Copy pentester lib and dashboard app
COPY pentester/ /app/pentest_lib/
COPY dashboard/ /app/

EXPOSE 8080
CMD ["python", "app.py"]
