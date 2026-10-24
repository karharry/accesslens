FROM python:3.13-slim

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION} PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/config TZ=UTC PORT=8089

# ctcat: copy of `cat` holding only CAP_DAC_READ_SEARCH, used to read the root-only host conntrack table
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && cp /bin/cat /usr/local/bin/ctcat && setcap cap_dac_read_search+ep /usr/local/bin/ctcat \
    && apt-get purge -y libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 accesslens && useradd -u 1000 -g 1000 -M -s /usr/sbin/nologin accesslens \
    && mkdir /config && chown 1000:1000 /config

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ /srv/app/

USER 1000:1000
WORKDIR /srv/app
VOLUME /config
EXPOSE 8089

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz'%os.environ.get('PORT','8089'),timeout=4)"

CMD ["sh", "-c", "exec uvicorn main:app --host ${BIND:-0.0.0.0} --port ${PORT} --proxy-headers --forwarded-allow-ips='*' --no-access-log"]
