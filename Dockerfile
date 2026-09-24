# ---- stage 1: build the Go scanner engine ----
FROM golang:1.26-alpine AS engine
WORKDIR /src
COPY engine/ ./
RUN CGO_ENABLED=0 go build -o sentinel-engine .

# ---- stage 2: build the React frontend ----
FROM node:20-alpine AS frontend
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- stage 3: Python backend + static UI ----
FROM python:3.13-slim
WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/ /app/backend/
COPY --from=engine /src/sentinel-engine /app/engine/sentinel-engine
COPY --from=frontend /app/dist /app/frontend/dist

ENV PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
