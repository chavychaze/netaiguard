# Інструкції з імплементації

## Підготовка системи
### Для запуску NetAIGuard на системі необхідно встановити наступні компоненти:

1. Docker і Docker Compose
2. Go 1.18 або новіше
3. Python 3.9 або новіше
4. Clang і LLVM для компіляції eBPF програм

```bash
# Встановлення Docker
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Встановлення Go
wget https://go.dev/dl/go1.18.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.18.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Встановлення Python
sudo apt-get install -y python3.9 python3-pip

# Встановлення Clang і LLVM для eBPF
sudo apt-get install -y clang llvm libbpf-dev
```

## Клонування репозиторію
### Підготуйте код, створивши всі файли, описані вище:
```bash
# Створення структури каталогів
mkdir -p netaiguard/{cmd,pkg,scripts,deploy}
mkdir -p netaiguard/pkg/{ebpf,ai,web,api,utils}
mkdir -p netaiguard/cmd/{ebpf-agent,api-server,web-ui}
mkdir -p netaiguard/deploy/{docker,kubernetes}

# Додайте всі необхідні файли, як описано вище
```

## Розгортання за допомогою Docker Compose
```bash
cd netaiguard/deploy/docker
docker-compose build
docker-compose up -d
```

Після успішного запуску, ви можете отримати доступ до компонентів:

- Web UI: http://localhost:8082
- API сервер: http://localhost:8081/api/health
- AI сервер: http://localhost:5000/health
- eBPF агент: http://localhost:8080/health

## Ручне розгортання (без Docker)
### Компіляція та запуск eBPF агента:
```bash
cd netaiguard
go build -o ebpf-agent ./cmd/ebpf-agent
sudo ./ebpf-agent --interface eth0 --rate-limit 100 --ai-server http://localhost:5000 --listen :8080
```

### Запуск AI сервера:
```bash
cd netaiguard/pkg/ai
pip install -r requirements.txt
python api.py
```

### Компіляція та запуск API сервера:
```bash
cd netaiguard
go build -o api-server ./cmd/api-server
./api-server --ebpf-agent http://localhost:8080 --ai-server http://localhost:5000 --listen :8081
```
