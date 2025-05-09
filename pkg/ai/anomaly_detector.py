#!/usr/bin/env python3
import pandas as pd
import numpy as np
import time
import json
import logging
from sklearn.ensemble import IsolationForest
from datetime import datetime

class AnomalyDetector:
    """Детектор аномалій на основі Isolation Forest"""
    
    def __init__(self, contamination=0.05):
        """
        Ініціалізація детектора аномалій
        
        Args:
            contamination: Очікувана частка аномалій у даних (за замовчуванням 5%)
        """
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1  # Використання всіх доступних ядер
        )
        self.is_trained = False
        self.logger = logging.getLogger("AnomalyDetector")
        
    def train(self, data):
        """
        Навчання моделі на наданих даних
        
        Args:
            data: DataFrame з характеристиками мережевого трафіку
                (наприклад, packets_per_second, bytes_per_second)
        
        Returns:
            self: Повертає сам об'єкт для ланцюжкових викликів
        """
        features = self._extract_features(data)
        
        if features.empty:
            self.logger.warning("No features available for training")
            return self
        
        self.logger.info(f"Training anomaly detection model on {len(features)} samples")
        self.model.fit(features)
        self.is_trained = True
        self.logger.info("Model training completed")
        
        return self
    
    def detect_anomalies(self, data):
        """
        Виявлення аномалій у наданих даних
        
        Args:
            data: DataFrame з характеристиками мережевого трафіку
        
        Returns:
            DataFrame з позначеними аномаліями та оцінками аномальності
        """
        if not self.is_trained:
            self.logger.warning("Model not trained yet. Training now...")
            self.train(data)
        
        features = self._extract_features(data)
        
        if features.empty:
            self.logger.warning("No features available for anomaly detection")
            return pd.DataFrame()
        
        # Створення копії вхідних даних
        result = data.copy()
        
        # Прогнозування аномалій (-1 для аномалій, 1 для нормальних точок)
        predictions = self.model.predict(features)
        
        # Отримання оцінок аномальності
        scores = self.model.decision_function(features)
        
        # Додавання результатів до вихідних даних
        result['anomaly'] = np.where(predictions == -1, 1, 0)  # 1 = аномалія, 0 = нормально
        result['anomaly_score'] = -scores  # Інвертуємо для зручності (вищі значення = більша аномальність)
        
        return result
    
    def _extract_features(self, data):
        """
        Вилучення ознак для виявлення аномалій
        
        Args:
            data: DataFrame вхідних даних
        
        Returns:
            DataFrame з ознаками для моделі
        """
        # Вибір релевантних ознак для аналізу
        relevant_features = [
            'packets_per_second', 
            'bytes_per_second'
        ]
        
        # Перевірка наявності всіх необхідних ознак
        available_features = [f for f in relevant_features if f in data.columns]
        
        if not available_features:
            return pd.DataFrame()
        
        # Вибір доступних ознак
        features = data[available_features].copy()
        
        # Заповнення відсутніх значень
        features.fillna(0, inplace=True)
        
        return features


class TrafficAnalyzer:
    """Аналізатор мережевого трафіку на базі детектора аномалій"""
    
    def __init__(self, anomaly_detector=None):
        """
        Ініціалізація аналізатора трафіку
        
        Args:
            anomaly_detector: Екземпляр детектора аномалій (опціонально)
        """
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.logger = logging.getLogger("TrafficAnalyzer")
    
    def analyze_traffic(self, ip_stats, window_seconds=10):
        """
        Аналіз статистики трафіку та виявлення аномалій
        
        Args:
            ip_stats: Словник з IP-статистикою {ip: {packets, bytes, last_seen}}
            window_seconds: Розмір вікна для розрахунку пакетів/секунду
        
        Returns:
            Dict з результатами аналізу та рекомендаціями
        """
        # Перетворення даних у DataFrame
        traffic_data = self._prepare_traffic_data(ip_stats, window_seconds)
        
        # Якщо даних немає, повертаємо порожній результат
        if traffic_data.empty:
            self.logger.warning("No traffic data available for analysis")
            return {
                "status": "no_data",
                "message": "No traffic data available for analysis",
                "timestamp": datetime.now().isoformat(),
                "recommendations": []
            }
        
        # Виявлення аномалій
        analysis_result = self.anomaly_detector.detect_anomalies(traffic_data)
        
        # Фільтрація аномалій
        anomalies = analysis_result[analysis_result['anomaly'] == 1]
        
        # Формування результатів
        result = {
            "status": "analysis_complete",
            "message": "Traffic analysis completed",
            "timestamp": datetime.now().isoformat(),
            "total_ips": len(traffic_data),
            "anomalies_count": len(anomalies),
            "top_ips_by_traffic": self._get_top_ips(traffic_data, 'bytes_per_second', 5),
            "top_ips_by_packets": self._get_top_ips(traffic_data, 'packets_per_second', 5),
            "recommendations": self._generate_recommendations(anomalies)
        }
        
        return result
    
    def _prepare_traffic_data(self, ip_stats, window_seconds):
        """
        Підготовка даних трафіку для аналізу
        
        Args:
            ip_stats: Словник з IP-статистикою
            window_seconds: Розмір вікна для розрахунку пакетів/секунду
        
        Returns:
            DataFrame з підготовленими даними
        """
        records = []
        now = time.time() * 1e9  # Поточний час у наносекундах
        
        for ip, stats in ip_stats.items():
            # Розрахунок характеристик за секунду
            packets = stats.get('packets', 0)
            bytes_count = stats.get('bytes', 0)
            last_seen = stats.get('last_seen', now)
            
            # Розрахунок метрик на основі вікна
            time_diff = max(1, (now - last_seen) / 1e9)  # Різниця в секундах
            packets_per_second = packets / min(time_diff, window_seconds)
            bytes_per_second = bytes_count / min(time_diff, window_seconds)
            
            records.append({
                'ip': ip,
                'packets': packets,
                'bytes': bytes_count,
                'packets_per_second': packets_per_second,
                'bytes_per_second': bytes_per_second,
                'last_seen': last_seen
            })
        
        if not records:
            return pd.DataFrame()
        
        return pd.DataFrame(records)
    
    def _get_top_ips(self, data, metric, limit=5):
        """
        Отримання IP з найвищим значенням метрики
        
        Args:
            data: DataFrame з даними трафіку
            metric: Назва метрики для сортування
            limit: Кількість IP для виведення
        
        Returns:
            List з top IP та їх метриками
        """
        if data.empty or metric not in data.columns:
            return []
        
        # Сортування за метрикою у спадному порядку
        top_data = data.sort_values(by=metric, ascending=False).head(limit)
        
        return [{'ip': row['ip'], metric: row[metric]} for _, row in top_data.iterrows()]
    
    def _generate_recommendations(self, anomalies):
        """
        Генерація рекомендацій на основі виявлених аномалій
        
        Args:
            anomalies: DataFrame з аномаліями
        
        Returns:
            List рекомендацій
        """
        recommendations = []
        
        for _, anomaly in anomalies.iterrows():
            ip = anomaly['ip']
            packets_per_second = anomaly['packets_per_second']
            bytes_per_second = anomaly['bytes_per_second']
            anomaly_score = anomaly['anomaly_score']
            
            # Визначення порогу для блокування (високий аномальний бал)
            if anomaly_score > 0.2:
                action = "block"
                reason = f"High anomaly score: {anomaly_score:.2f}, Packets/sec: {packets_per_second:.2f}"
                confidence = min(0.95, 0.7 + anomaly_score / 4)  # Масштабування 0.7-0.95
            elif packets_per_second > 100:  # Приклад порогу
                action = "rate_limit"
                reason = f"High packet rate: {packets_per_second:.2f} packets/sec"
                confidence = 0.85
            else:
                action = "monitor"
                reason = f"Unusual traffic pattern detected"
                confidence = 0.7
            
            recommendations.append({
                'ip': ip,
                'action': action,
                'reason': reason,
                'metrics': {
                    'packets_per_second': float(packets_per_second),
                    'bytes_per_second': float(bytes_per_second),
                    'anomaly_score': float(anomaly_score)
                },
                'confidence': confidence
            })
        
        return recommendations


if __name__ == "__main__":
    # Налаштування логування
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Створення детектора аномалій та аналізатора трафіку
    detector = AnomalyDetector()
    analyzer = TrafficAnalyzer(detector)
    
    # Приклад використання
    test_data = {
        "192.168.1.1": {"packets": 100, "bytes": 15000, "last_seen": time.time() * 1e9},
        "192.168.1.2": {"packets": 5000, "bytes": 750000, "last_seen": time.time() * 1e9},
        "192.168.1.3": {"packets": 200, "bytes": 30000, "last_seen": time.time() * 1e9}
    }
    
    # Аналіз трафіку
    result = analyzer.analyze_traffic(test_data)
    print(json.dumps(result, indent=2))