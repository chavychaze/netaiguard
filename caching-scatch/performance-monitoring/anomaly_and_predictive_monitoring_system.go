// Performance Monitoring and Anomaly Detection System
package monitoring

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/yourusername/netaiguard/pkg/ai"
	"github.com/yourusername/netaiguard/pkg/alerts"
	"github.com/yourusername/netaiguard/pkg/config"
	"github.com/yourusername/netaiguard/pkg/storage"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// AnomalyDetectionSystem виявляє аномалії в метриках продуктивності
type AnomalyDetectionSystem struct {
    config          *config.MonitoringConfig
    promClient      v1.API
    aiPredictor     *ai.MetricPredictor
    storageManager  *storage.StorageManager
    alertManager    *alerts.AlertManager
    stopCh          chan struct{}
}

// MetricAnomaly представляє виявлену аномалію
type MetricAnomaly struct {
    Timestamp    time.Time
    MetricName   string
    Labels       map[string]string
    ExpectedValue float64
    ActualValue  float64
    Deviation    float64
    Severity     string
}

// NewAnomalyDetectionSystem створює нову систему виявлення аномалій
func NewAnomalyDetectionSystem(
    ctx context.Context,
    config *config.MonitoringConfig,
    predictor *ai.MetricPredictor,
    storageManager *storage.StorageManager,
    alertManager *alerts.AlertManager) (*AnomalyDetectionSystem, error) {
    
    // Ініціалізація клієнта Prometheus
    promConfig := api.Config{
        Address: config.PrometheusURL,
    }
    promClient, err := api.NewClient(promConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create Prometheus client: %w", err)
    }
    
    return &AnomalyDetectionSystem{
        config:         config,
        promClient:     v1.NewAPI(promClient),
        aiPredictor:    predictor,
        storageManager: storageManager,
        alertManager:   alertManager,
        stopCh:         make(chan struct{}),
    }, nil
}

// Start запускає систему виявлення аномалій
func (ads *AnomalyDetectionSystem) Start(ctx context.Context) error {
    // Запуск періодичної перевірки метрик
    go ads.runAnomalyDetectionLoop(ctx)
    
    return nil
}

// Stop зупиняє систему виявлення аномалій
func (ads *AnomalyDetectionSystem) Stop() {
    close(ads.stopCh)
}

// runAnomalyDetectionLoop запускає цикл виявлення аномалій
func (ads *AnomalyDetectionSystem) runAnomalyDetectionLoop(ctx context.Context) {
    ticker := time.NewTicker(ads.config.AnomalyDetectionInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ads.stopCh:
            return
        case <-ctx.Done():
            return
        case <-ticker.C:
            if err := ads.detectAnomalies(ctx); err != nil {
                fmt.Printf("Error during anomaly detection: %v\n", err)
            }
        }
    }
}

// detectAnomalies виявляє аномалії в метриках
func (ads *AnomalyDetectionSystem) detectAnomalies(ctx context.Context) error {
    // Проходимо по всім метрикам, які ми хочемо аналізувати
    for _, metricConfig := range ads.config.MonitoredMetrics {
        metricName := metricConfig.Name
        query := metricConfig.Query
        
        // Отримання поточних значень метрик з Prometheus
        result, _, err := ads.promClient.Query(ctx, query, time.Now())
        if err != nil {
            return fmt.Errorf("failed to query Prometheus: %w", err)
        }
        
        // Перевірка кожного значення на аномалії
        vector, ok := result.(model.Vector)
        if !ok {
            return fmt.Errorf("unexpected result format for metric %s", metricName)
        }
        
        for _, sample := range vector {
            // Перетворення міток у мапу
            labels := make(map[string]string)
            for k, v := range sample.Metric {
                labels[string(k)] = string(v)
            }
            
            // Отримання прогнозованого значення з предиктора
            prediction, err := ads.aiPredictor.PredictMetricValue(ctx, metricName, labels, time.Now())
            if err != nil {
                fmt.Printf("Failed to predict value for metric %s: %v\n", metricName, err)
                continue
            }
            
            // Порівняння поточного значення з прогнозованим
            actualValue := float64(sample.Value)
            expectedValue := prediction.Value
            
            // Розрахунок відхилення
            deviation := calculateDeviation(actualValue, expectedValue)
            
            // Якщо відхилення перевищує поріг - це аномалія
            if deviation > metricConfig.AnomalyThreshold {
                anomaly := MetricAnomaly{
                    Timestamp:     time.Now(),
                    MetricName:    metricName,
                    Labels:        labels,
                    ExpectedValue: expectedValue,
                    ActualValue:   actualValue,
                    Deviation:     deviation,
                    Severity:      getSeverity(deviation, metricConfig.SeverityThresholds),
                }
                
                // Зберігаємо аномалію
                if err := ads.storeAnomaly(ctx, anomaly); err != nil {
                    fmt.Printf("Failed to store anomaly: %v\n", err)
                }
                
                // Генеруємо сповіщення
                if err := ads.triggerAlert(ctx, anomaly); err != nil {
                    fmt.Printf("Failed to trigger alert: %v\n", err)
                }
            }
        }
    }
    
    return nil
}

// calculateDeviation розраховує відхилення між значеннями
func calculateDeviation(actual, expected float64) float64 {
    if expected == 0 {
        // Уникаємо ділення на нуль
        if actual == 0 {
            return 0
        }
        return 1.0 // 100% відхилення, якщо очікувалось 0
    }
    
    return math.Abs((actual - expected) / expected)
}

// getSeverity визначає серйозність аномалії
func getSeverity(deviation float64, thresholds map[string]float64) string {
    // Стандартні пороги, якщо не налаштовані інші
    if thresholds == nil || len(thresholds) == 0 {
        thresholds = map[string]float64{
            "warning":  0.1,  // 10% відхилення
            "critical": 0.3,  // 30% відхилення
        }
    }
    
    // Визначення серйозності на основі порогів
    if deviation >= thresholds["critical"] {
        return "critical"
    } else if deviation >= thresholds["warning"] {
        return "warning"
    }
    
    return "info"
}

// storeAnomaly зберігає аномалію в сховище даних
func (ads *AnomalyDetectionSystem) storeAnomaly(ctx context.Context, anomaly MetricAnomaly) error {
    // Перетворення аномалії на карту для зберігання
    anomalyMap := map[string]interface{}{
        "timestamp":     anomaly.Timestamp,
        "metric_name":   anomaly.MetricName,
        "labels":        anomaly.Labels,
        "expected_value": anomaly.ExpectedValue,
        "actual_value":  anomaly.ActualValue,
        "deviation":     anomaly.Deviation,
        "severity":      anomaly.Severity,
    }
    
    // Збереження в документній базі даних
    return ads.storageManager.StoreEvent(ctx, anomalyMap, "anomalies")
}

// triggerAlert генерує сповіщення про аномалію
func (ads *AnomalyDetectionSystem) triggerAlert(ctx context.Context, anomaly MetricAnomaly) error {
    // Форматування повідомлення для сповіщення
    description := fmt.Sprintf(
        "Anomaly detected in metric %s. Expected: %.4f, Actual: %.4f, Deviation: %.2f%%",
        anomaly.MetricName,
        anomaly.ExpectedValue,
        anomaly.ActualValue,
        anomaly.Deviation*100,
    )
    
    // Додавання контексту з мітками
    var labelsStr string
    for k, v := range anomaly.Labels {
        labelsStr += fmt.Sprintf("%s=%s, ", k, v)
    }
    if len(labelsStr) > 0 {
        labelsStr = labelsStr[:len(labelsStr)-2] // Видалення останньої коми та пробілу
    }
    
    alert := &alerts.Alert{
        Name:        fmt.Sprintf("AnomalyDetection_%s", anomaly.MetricName),
        Severity:    anomaly.Severity,
        Description: description,
        Labels:      anomaly.Labels,
        Context:     map[string]interface{}{
            "metric_name":    anomaly.MetricName,
            "labels":         labelsStr,
            "expected_value": anomaly.ExpectedValue,
            "actual_value":   anomaly.ActualValue,
            "deviation":      anomaly.Deviation,
            "timestamp":      anomaly.Timestamp,
        },
    }
    
    // Відправлення сповіщення
    return ads.alertManager.SendAlert(ctx, alert)
}