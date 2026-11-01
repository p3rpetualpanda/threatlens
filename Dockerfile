FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:0.9.5 /uv /usr/local/bin/uv
WORKDIR /srv
ENV PATH="/srv/.venv/bin:$PATH" THREATLENS_DB_PATH=/data/threatlens.db UV_COMPILE_BYTECODE=1
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY app app
COPY config config
COPY contracts contracts
COPY demo demo
COPY scripts/seed_demo.py scripts/seed_demo.py
RUN uv sync --locked --no-dev \
    && useradd --system --uid 10001 app && mkdir /data && chown app /data
USER app
EXPOSE 8000
# Seeds on first start only, then serves. The password is printed in the container log once.
CMD ["sh", "-c", "python scripts/seed_demo.py \"$THREATLENS_DB_PATH\" demo/beacon_findings.jsonl config && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
