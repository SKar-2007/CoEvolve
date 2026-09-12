FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY packages/ packages/

EXPOSE 8000

CMD ["uvicorn", "packages.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
