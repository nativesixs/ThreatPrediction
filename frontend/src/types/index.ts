// Prediction types
export interface Prediction {
  id: number;
  timestamp: string;
  traffic_log_id?: number;
  model_name: string;
  predicted_class: string;
  confidence_score: number;
  is_attack: boolean;
  all_probabilities?: Record<string, number>;
  processing_time_ms?: number;
}

export interface PredictionCreate {
  traffic_log_id?: number;
  model_name: string;
  predicted_class: string;
  confidence_score: number;
  is_attack: boolean;
  all_probabilities?: Record<string, number>;
  processing_time_ms?: number;
}

// Traffic types
export interface TrafficLog {
  id: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  packet_length: number;
  flags?: string;
  features?: Record<string, any>;
  raw_data?: string;
}

export interface TrafficStats {
  time_window_minutes: number;
  total_packets: number;
  protocols: Record<string, number>;
  top_sources: Array<{ ip: string; count: number }>;
  top_destinations: Array<{ ip: string; count: number }>;
}

// Model Metrics types
export interface ModelMetrics {
  id: number;
  timestamp: string;
  model_name: string;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  confusion_matrix?: number[][];
  roc_auc?: number;
  training_time?: number;
}

export interface ModelComparison {
  models: Array<{
    model_name: string;
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1_score?: number;
    timestamp?: string;
  }>;
  best_accuracy: number;
  best_f1: number;
}

// WebSocket Message types
export interface WebSocketMessage {
  type: 'prediction' | 'alert' | 'stats' | 'connection' | 'heartbeat' | 'pong' | 'error';
  data?: any;
  timestamp?: string;
}

export interface PredictionMessage {
  prediction: {
    predicted_class: string;
    predicted_label: string;
    confidence: number;
    is_attack: boolean;
    all_probabilities: Record<string, number>;
  };
  packet_info: {
    source_ip?: string;
    destination_ip?: string;
    protocol?: string;
    timestamp?: string;
  };
}

// Alert types
export interface Alert {
  id: number;
  timestamp: string;
  prediction_id?: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  alert_type: string;
  message: string;
  acknowledged: boolean;
}

// API Response types
export interface ApiResponse<T> {
  data: T;
  status: number;
  message?: string;
}

export interface PaginationParams {
  limit?: number;
  skip?: number;
}

export interface FilterParams extends PaginationParams {
  is_attack?: boolean;
  model_name?: string;
  source_ip?: string;
  destination_ip?: string;
  protocol?: string;
}

// Chart data types
export interface ChartDataPoint {
  time: string;
  confidence?: number;
  isAttack?: number;
  value?: number;
  [key: string]: any;
}

// Settings types
export interface AppSettings {
  apiUrl: string;
  wsUrl: string;
  refreshInterval: number;
  maxRecentAttacks: number;
  enableNotifications: boolean;
  enableAutoReconnect: boolean;
}

// Health Check types
export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  kafka_consumer?: {
    running: boolean;
    packets_consumed: number;
    batches_processed: number;
  };
  websocket_connections?: number;
}
