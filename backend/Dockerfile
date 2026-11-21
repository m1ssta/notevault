# build context = repository root (see docker-compose.yml)
FROM python:3.12-slim
RUN useradd --no-create-home --uid 10001 app
WORKDIR /srv
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY frontend ./static
ENV NOTEVAULT_STATIC_DIR=/srv/static
USER 10001
CMD ["uvicorn", "app.wsgi:app", "--host", "0.0.0.0", "--port", "8000"]
