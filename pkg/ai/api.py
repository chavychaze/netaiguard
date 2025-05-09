#!/usr/bin/env python3
import json
import logging
import os
import time
from flask import Flask, request, jsonify
from anomaly_detector import AnomalyDetector, TrafficAnalyzer

# Налаштування логування
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AI-API")

# Ініціалізація Flask додатку
app = Flask(__name__)

# Ініціалізація AI компонентів
detector = AnomalyDetector()
analyzer = TrafficAnalyzer(detector)

@app.route('/health', methods=['GET'])
def health_check():
    """Перевірка стану API"""
    return jsonify({
        'status': 'ok',
        'message': 'AI API is running',
        'timestamp': time.time()
    })

@app.route('/analyze', methods=['POST'])
def analyze_traffic():
    """
    Аналіз мережевого трафіку та виявлення аномалій
    
    Очікує POST запит з JSON body:
    {
        "ip_stats": {
            "ip1": {"packets": N, "bytes": M, "last_seen": timestamp},
            "ip2": {"packets": N, "bytes": M, "last_seen": timestamp},
            ...
        },
        "window_seconds": 10  # опціонально
    }
    """
    try:
        data = request.json
        
        if not data or not isinstance(data, dict) or 'ip_stats' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Invalid request: missing ip_stats field'
            }), 400
        
        ip_stats = data.get('ip_stats', {})
        window_seconds = data.get('window_seconds', 10)
        
        # Виконання аналізу трафіку
        logger.info(f"Analyzing traffic data for {len(ip_stats)} IP addresses")
        result = analyzer.analyze_traffic(ip_stats, window_seconds)
        
        return jsonify(result)
    
    except Exception as e:
        logger.exception(f"Error analyzing traffic: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error analyzing traffic: {str(e)}'
        }), 500

@app.route('/train', methods=['POST'])
def train_model():
    """
    Навчання моделі виявлення аномалій
    
    Очікує POST запит з JSON body:
    {
        "training_data": [
            {"ip": "ip1", "packets": N, "bytes": M, "packets_per_second": X, "bytes_per_second": Y},
            {"ip": "ip2", "packets": N, "bytes": M, "packets_per_second": X, "bytes_per_second": Y},
            ...
        ]
    }
    """
    try:
        data = request.json
        
        if not data or not isinstance(data, dict) or 'training_data' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Invalid request: missing training_data field'
            }), 400
        
        training_data = data.get('training_data', [])
        
        if not training_data or not isinstance(training_data, list):
            return jsonify({
                'status': 'error',
                'message': 'Invalid request: training_data must be a non-empty list'
            }), 400
        
        # Конвертація даних у DataFrame
        import pandas as pd
        df = pd.DataFrame(training_data)
        
        # Перевірка необхідних колонок
        required_columns = ['packets_per_second', 'bytes_per_second']
        for col in required_columns:
            if col not in df.columns:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid request: training_data must contain {col} column'
                }), 400
        
        # Навчання моделі
        logger.info(f"Training anomaly detection model with {len(df)} samples")
        detector.train(df)
        
        return jsonify({
            'status': 'success',
            'message': 'Model trained successfully',
            'samples_count': len(df)
        })
    
    except Exception as e:
        logger.exception(f"Error training model: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error training model: {str(e)}'
        }), 500

@app.route('/detect', methods=['POST'])
def detect_anomalies():
    """
    Виявлення аномалій у наданих даних
    
    Очікує POST запит з JSON body:
    {
        "traffic_data": [
            {"ip": "ip1", "packets": N, "bytes": M, "packets_per_second": X, "bytes_per_second": Y},
            {"ip": "ip2", "packets": N, "bytes": M, "packets_per_second": X, "bytes_per_second": Y},
            ...
        ]
    }
    """
    try:
        data = request.json
        
        if not data or not isinstance(data, dict) or 'traffic_data' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Invalid request: missing traffic_data field'
            }), 400
        
        traffic_data = data.get('traffic_data', [])
        
        # Конвертація даних у DataFrame
        import pandas as pd
        df = pd.DataFrame(traffic_data)
        
        if df.empty:
            return jsonify({
                'status': 'error',
                'message': 'Invalid request: traffic_data is empty'
            }), 400
        
        # Перевірка моделі
        if not detector.is_trained:
            return jsonify({
                'status': 'error',
                'message': 'Model not trained yet'
            }), 400
        
        # Виявлення аномалій
        result_df = detector.detect_anomalies(df)
        
        # Конвертація результатів у список для JSON
        anomalies = result_df[result_df['anomaly'] == 1].to_dict('records')
        
        return jsonify({
            'status': 'success',
            'message': 'Anomaly detection completed',
            'total_samples': len(result_df),
            'anomalies_count': len(anomalies),
            'anomalies': anomalies
        })
    
    except Exception as e:
        logger.exception(f"Error detecting anomalies: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error detecting anomalies: {str(e)}'
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    
    logger.info(f"Starting AI API on {host}:{port}")
    app.run(host=host, port=port)