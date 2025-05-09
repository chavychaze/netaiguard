FROM golang:1.18 AS builder

WORKDIR /app

# Копіювання Go модуля
COPY go.mod go.sum ./
RUN go mod download

# Копіювання коду
COPY . .

# Компіляція Web UI сервера
RUN go build -o /web-ui ./cmd/web-ui

# Підготовка робочого контейнера
FROM debian:bullseye-slim

WORKDIR /app

# Копіювання бінарного файлу та статичних файлів
COPY --from=builder /web-ui /app/web-ui
COPY pkg/web /app/pkg/web

EXPOSE 8082

ENTRYPOINT ["/app/web-ui"]