FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git perl libnet-ssleay-perl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# Install Nuclei (Go binary from ProjectDiscovery)
RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sLo /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" \
    && unzip -qo /tmp/nuclei.zip -d /tmp/nuclei_bin/ \
    && mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei_bin/

# Install Python deps from both pentester and dashboard requirements
COPY pentester/requirements.txt /tmp/pentest_req.txt
COPY dashboard/requirements.txt /tmp/dash_req.txt
RUN pip install --no-cache-dir -r /tmp/pentest_req.txt -r /tmp/dash_req.txt

# Copy pentester lib and dashboard app
COPY pentester/ /app/pentest_lib/
COPY dashboard/ /app/

EXPOSE 8080
CMD ["python", "app.py"]
