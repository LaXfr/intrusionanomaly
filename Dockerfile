FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
COPY src ./src
COPY api ./api
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic
COPY configs ./configs
COPY models ./models
RUN pip install --no-cache-dir '.[api,database,data,parquet,preprocessing]'

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
