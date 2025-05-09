FROM golang:1.18 AS builder

WORKDIR /app

# Встановлення залежностей для eBPF
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Копіювання Go модуля
COPY go.mod go.sum ./
RUN go mod download

# Копіювання коду
COPY . .

# Компіляція eBPF агента
RUN go build -o /ebpf-agent ./cmd/ebpf-agent

# Підготовка робочого контейнера
FROM debian:bullseye-slim

# Встановлення необхідних пакетів
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копіювання бінарного файлу та eBPF коду
COPY --from=builder /ebpf-agent /app/ebpf-agent
COPY pkg/ebpf/xdp_filter.c /app/pkg/ebpf/xdp_filter.c

EXPOSE 8080

ENTRYPOINT ["/app/ebpf-agent"]