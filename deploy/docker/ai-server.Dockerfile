FROM python:3.9-slim

WORKDIR /app

# Встановлення залежностей
COPY pkg/ai/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Копіювання Python коду
COPY pkg/ai/anomaly_detector.py pkg/ai/api.py ./

EXPOSE 5000

# Запуск API сервера
CMD ["python", "api.py"]