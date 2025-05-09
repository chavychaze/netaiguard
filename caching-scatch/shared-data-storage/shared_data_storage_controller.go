// Distributed Storage Manager
package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/yourusername/netaiguard/pkg/config"
	"github.com/yourusername/netaiguard/pkg/encryption"
	"github.com/yourusername/netaiguard/pkg/metrics"

	"github.com/go-redis/redis/v8"
	"github.com/minio/minio-go/v7"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// StorageManager управляє різними типами розподіленого зберігання
type StorageManager struct {
    config           *config.StorageConfig
    timeSeriesDB     influxdb2.Client
    documentDB       *mongo.Client
    keyValueStore    *redis.ClusterClient
    objectStorage    *minio.Client
    encryptionSvc    *encryption.Service
    metricsClient    *metrics.Client
}

// StorageType тип сховища
type StorageType string

const (
    TimeSeries  StorageType = "timeseries"
    Document    StorageType = "document"
    KeyValue    StorageType = "keyvalue"
    Object      StorageType = "object"
)

// NewStorageManager створює новий менеджер зберігання
func NewStorageManager(
    ctx context.Context,
    config *config.StorageConfig,
    encryptionSvc *encryption.Service,
    metricsClient *metrics.Client) (*StorageManager, error) {
    
    sm := &StorageManager{
        config:        config,
        encryptionSvc: encryptionSvc,
        metricsClient: metricsClient,
    }
    
    // Ініціалізація InfluxDB для часових рядів
    tdb := influxdb2.NewClient(config.TimeSeriesDB.URL, config.TimeSeriesDB.Token)
    _, err := tdb.Ready(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to InfluxDB: %w", err)
    }
    sm.timeSeriesDB = tdb
    
    // Ініціалізація MongoDB для документів
    mongoOpts := options.Client().ApplyURI(config.DocumentDB.URI)
    mongoClient, err := mongo.Connect(ctx, mongoOpts)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
    }
    if err := mongoClient.Ping(ctx, nil); err != nil {
        return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
    }
    sm.documentDB = mongoClient
    
    // Ініціалізація Redis для ключ-значення
    redisOpt := &redis.ClusterOptions{
        Addrs:    config.KeyValueStore.Addresses,
        Password: config.KeyValueStore.Password,
    }
    redisClient := redis.NewClusterClient(redisOpt)
    if _, err := redisClient.Ping(ctx).Result(); err != nil {
        return nil, fmt.Errorf("failed to connect to Redis: %w", err)
    }
    sm.keyValueStore = redisClient
    
    // Ініціалізація MinIO для об'єктного зберігання
    minioClient, err := minio.New(
        config.ObjectStorage.Endpoint,
        &minio.Options{
            Creds:  minio.NewStaticCredentials(config.ObjectStorage.AccessKey, config.ObjectStorage.SecretKey, ""),
            Secure: config.ObjectStorage.UseSSL,
        },
    )
    if err != nil {
        return nil, fmt.Errorf("failed to initialize MinIO client: %w", err)
    }
    sm.objectStorage = minioClient
    
    return sm, nil
}

// Close закриває всі з'єднання
func (sm *StorageManager) Close() {
    sm.timeSeriesDB.Close()
    sm.documentDB.Disconnect(context.Background())
    sm.keyValueStore.Close()
}

// StoreMetrics зберігає метрики в часовій базі даних
func (sm *StorageManager) StoreMetrics(ctx context.Context, metrics []metrics.Metric) error {
    writeAPI := sm.timeSeriesDB.WriteAPI(
        sm.config.TimeSeriesDB.Organization,
        sm.config.TimeSeriesDB.Bucket,
    )
    
    for _, metric := range metrics {
        point := influxdb2.NewPoint(
            metric.Name,
            metric.Tags,
            metric.Fields,
            metric.Timestamp,
        )
        writeAPI.WritePoint(point)
    }
    
    writeAPI.Flush()
    return nil
}

// StoreEvent зберігає подію в документній базі даних
func (sm *StorageManager) StoreEvent(ctx context.Context, event map[string]interface{}, collection string) error {
    // Додаємо мітку часу, якщо вона не встановлена
    if _, ok := event["timestamp"]; !ok {
        event["timestamp"] = time.Now()
    }
    
    // Шифрування чутливих полів
    if sensitiveFields, ok := event["sensitive"].([]string); ok {
        for _, field := range sensitiveFields {
            if val, exists := event[field]; exists {
                if strVal, ok := val.(string); ok {
                    encVal, err := sm.encryptionSvc.Encrypt(strVal)
                    if err != nil {
                        return fmt.Errorf("failed to encrypt sensitive field: %w", err)
                    }
                    event[field] = encVal
                }
            }
        }
        // Видаляємо маркер чутливих полів
        delete(event, "sensitive")
    }
    
    // Збереження в MongoDB
    coll := sm.documentDB.Database(sm.config.DocumentDB.Database).Collection(collection)
    _, err := coll.InsertOne(ctx, event)
    if err != nil {
        return fmt.Errorf("failed to store event: %w", err)
    }
    
    return nil
}

// Get отримує дані з ключ-значення сховища
func (sm *StorageManager) Get(ctx context.Context, key string) (string, error) {
    val, err := sm.keyValueStore.Get(ctx, key).Result()
    if err != nil {
        return "", fmt.Errorf("failed to get value for key %s: %w", key, err)
    }
    return val, nil
}

// Set встановлює дані в ключ-значення сховище
func (sm *StorageManager) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
    err := sm.keyValueStore.Set(ctx, key, value, ttl).Err()
    if err != nil {
        return fmt.Errorf("failed to set value for key %s: %w", key, err)
    }
    return nil
}

// StoreObject зберігає об'єкт у об'єктне сховище
func (sm *StorageManager) StoreObject(
    ctx context.Context,
    bucketName string,
    objectName string,
    data []byte,
    contentType string) error {
    
    // Перевіряємо існування бакета, якщо його немає - створюємо
    exists, err := sm.objectStorage.BucketExists(ctx, bucketName)
    if err != nil {
        return fmt.Errorf("failed to check bucket existence: %w", err)
    }
    
    if !exists {
        err = sm.objectStorage.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
        if err != nil {
            return fmt.Errorf("failed to create bucket: %w", err)
        }
    }
    
    // Збереження об'єкта
    reader := bytes.NewReader(data)
    _, err = sm.objectStorage.PutObject(ctx, bucketName, objectName, reader, int64(len(data)),
        minio.PutObjectOptions{ContentType: contentType})
    if err != nil {
        return fmt.Errorf("failed to store object: %w", err)
    }
    
    return nil
}

// GetObject отримує об'єкт з об'єктного сховища
func (sm *StorageManager) GetObject(
    ctx context.Context,
    bucketName string,
    objectName string) ([]byte, error) {
    
    // Отримання об'єкта
    obj, err := sm.objectStorage.GetObject(ctx, bucketName, objectName, minio.GetObjectOptions{})
    if err != nil {
        return nil, fmt.Errorf("failed to get object: %w", err)
    }
    defer obj.Close()
    
    // Зчитування даних
    var buffer bytes.Buffer
    if _, err := io.Copy(&buffer, obj); err != nil {
        return nil, fmt.Errorf("failed to read object data: %w", err)
    }
    
    return buffer.Bytes(), nil
}