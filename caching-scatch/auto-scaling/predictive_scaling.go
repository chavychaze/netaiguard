// Predictive Auto-scaler
package autoscaling

import (
	"context"
	"fmt"
	"time"

	"github.com/yourusername/netaiguard/pkg/ai"
	"github.com/yourusername/netaiguard/pkg/metrics"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PredictiveScaler прогнозує навантаження та проактивно масштабує ресурси
type PredictiveScaler struct {
    k8sClient      *kubernetes.Clientset
    metricsClient  *metrics.Client
    predictor      *ai.LoadPredictor
    config         *ScalerConfig
    namespace      string
    deployments    []string
}

// ScalerConfig містить налаштування для предиктивного масштабування
type ScalerConfig struct {
    PredictionHorizon      time.Duration   // Наскільки далеко прогнозувати (напр., 30 хв)
    UpdateFrequency        time.Duration   // Частота оновлення прогнозу (напр., 5 хв)
    MinReplicas            int32           // Мінімальна кількість реплік
    MaxReplicas            int32           // Максимальна кількість реплік
    ScaleUpCooldown        time.Duration   // Період очікування між масштабуваннями вгору
    ScaleDownCooldown      time.Duration   // Період очікування між масштабуваннями вниз
    TargetCPUUtilization   int32           // Цільове використання CPU (у відсотках)
    TargetMemoryUsage      int32           // Цільове використання пам'яті (у відсотках)
    SafetyFactor           float64         // Коефіцієнт запасу для прогнозів (напр., 1.2)
    SeasonalPatterns       []string        // Набір сезонних патернів (напр., "daily", "weekly")
}

// NewPredictiveScaler створює новий екземпляр предиктивного масштабувальника
func NewPredictiveScaler(
    k8sClient *kubernetes.Clientset,
    metricsClient *metrics.Client,
    predictor *ai.LoadPredictor,
    config *ScalerConfig,
    namespace string,
    deployments []string) *PredictiveScaler {
    
    return &PredictiveScaler{
        k8sClient:   k8sClient,
        metricsClient: metricsClient,
        predictor:   predictor,
        config:      config,
        namespace:   namespace,
        deployments: deployments,
    }
}

// Start запускає цикл предиктивного масштабування
func (ps *PredictiveScaler) Start(ctx context.Context) error {
    ticker := time.NewTicker(ps.config.UpdateFrequency)
    defer ticker.Stop()
    
    // Попереднє навчання предиктора на історичних даних
    if err := ps.trainPredictor(); err != nil {
        return fmt.Errorf("failed to train predictor: %w", err)
    }
    
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            if err := ps.updateScaling(); err != nil {
                // Логуємо помилку, але продовжуємо роботу
                fmt.Printf("Error during scaling update: %v\n", err)
            }
        }
    }
}

// trainPredictor навчає предиктор на історичних даних
func (ps *PredictiveScaler) trainPredictor() error {
    // Отримуємо історичні метрики для навчання
    endTime := time.Now()
    startTime := endTime.Add(-30 * 24 * time.Hour) // 30 днів історії
    
    historicalData, err := ps.metricsClient.GetHistoricalMetrics(
        ps.namespace,
        ps.deployments,
        startTime,
        endTime,
    )
    if err != nil {
        return fmt.Errorf("failed to get historical metrics: %w", err)
    }
    
    // Навчання предиктора
    trainingConfig := &ai.TrainingConfig{
        SeasonalPatterns: ps.config.SeasonalPatterns,
        FeatureColumns:   []string{"cpu_usage", "memory_usage", "request_rate"},
        TargetColumn:     "required_replicas",
    }
    
    if err := ps.predictor.Train(historicalData, trainingConfig); err != nil {
        return fmt.Errorf("failed to train predictor: %w", err)
    }
    
    return nil
}

// updateScaling оновлює масштабування на основі прогнозу
func (ps *PredictiveScaler) updateScaling() error {
    // Для кожного розгортання у списку
    for _, deployment := range ps.deployments {
        // Отримуємо поточний стан розгортання
        deploy, err := ps.k8sClient.AppsV1().Deployments(ps.namespace).
            Get(context.Background(), deployment, metav1.GetOptions{})
        if err != nil {
            return fmt.Errorf("failed to get deployment %s: %w", deployment, err)
        }
        
        // Отримуємо поточні метрики
        currentMetrics, err := ps.metricsClient.GetCurrentMetrics(ps.namespace, deployment)
        if err != nil {
            return fmt.Errorf("failed to get current metrics for %s: %w", deployment, err)
        }
        
        // Прогнозуємо навантаження
        predictions, err := ps.predictor.PredictLoad(
            deployment,
            time.Now(),
            time.Now().Add(ps.config.PredictionHorizon),
        )
        if err != nil {
            return fmt.Errorf("failed to predict load for %s: %w", deployment, err)
        }
        
        // Визначаємо максимальне прогнозоване навантаження у горизонті прогнозування
        maxPredictedLoad := 0.0
        for _, prediction := range predictions {
            if prediction.PredictedLoad > maxPredictedLoad {
                maxPredictedLoad = prediction.PredictedLoad
            }
        }
        
        // Додаємо коефіцієнт запасу
        maxPredictedLoad *= ps.config.SafetyFactor
        
        // Розраховуємо необхідну кількість реплік
        currentReplicas := *deploy.Spec.Replicas
        currentLoad := currentMetrics.CPUUtilization
        
        // Базовий розрахунок: пропорційне масштабування на основі поточного навантаження
        predictedReplicas := int32(float64(currentReplicas) * (maxPredictedLoad / float64(currentLoad)))
        
        // Обмеження мінімальною та максимальною кількістю реплік
        if predictedReplicas < ps.config.MinReplicas {
            predictedReplicas = ps.config.MinReplicas
        }
        if predictedReplicas > ps.config.MaxReplicas {
            predictedReplicas = ps.config.MaxReplicas
        }
        
        // Оновлюємо кількість реплік, якщо вона змінилася
        if predictedReplicas != currentReplicas {
            deploy.Spec.Replicas = &predictedReplicas
            _, err = ps.k8sClient.AppsV1().Deployments(ps.namespace).
                Update(context.Background(), deploy, metav1.UpdateOptions{})
            if err != nil {
                return fmt.Errorf("failed to update deployment %s: %w", deployment, err)
            }
            
            fmt.Printf("Scaled deployment %s from %d to %d replicas based on predicted load\n",
                deployment, currentReplicas, predictedReplicas)
        }
    }
    
    return nil
}