FROM golang:1.18 AS builder

WORKDIR /app

# Копіювання Go модуля
COPY go.mod go.sum ./
RUN go mod download

# Копіювання коду
COPY . .

# Компіляція API сервера
RUN go build -o /api-server ./cmd/api-server

# Підготовка робочого контейнера
FROM debian:bullseye-slim

WORKDIR /app

# Копіювання бінарного файлу
COPY --from=builder /api-server /app/api-server

EXPOSE 8081

ENTRYPOINT ["/app/api-server"]