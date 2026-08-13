# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Instagram session state and rate-limit counters are both resolved from
# Path.home(), so HOME is pointed at the volume: everything the container
# needs to persist across restarts lands in one mount.
ENV HOME=/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Requirements are fully pinned, so this layer is cached until they change.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY auth.py ./
COPY src/ ./src/

# Run unprivileged; the volume mount point has to be owned by that user or the
# first session write fails.
RUN useradd --uid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown -R app:app /data
USER app
VOLUME ["/data"]

# stdio is unreachable from outside a container, so HTTP is the default here.
# 0.0.0.0 binds inside the container's namespace only — the port is not
# reachable until you publish it with -p.
ENV MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_PATH=/mcp
EXPOSE 8000

# ENTRYPOINT is the interpreter so the one-time interactive sign-in is just
# `docker run -it <image> auth.py`.
ENTRYPOINT ["python"]
CMD ["src/mcp_server.py"]
