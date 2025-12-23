import axios, { AxiosResponse } from 'axios';
import type { 
  Prediction, 
  TrafficLog, 
  ModelMetrics, 
  ApiResponse, 
  HealthStatus 
} from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const API_PREFIX = '/api';

const api = axios.create({
  baseURL: `${API_BASE_URL}${API_PREFIX}`,
  headers: {
    'Content-Type': 'application/json',
  },
});

interface QueryParams {
  page?: number;
  limit?: number;
  [key: string]: any;
}

// Anomalies API (replaces Predictions)
export const anomaliesAPI = {
  getAll: (params: QueryParams = {}): Promise<AxiosResponse<ApiResponse<any[]>>> => 
    api.get('/anomalies', { params }),
  getRecent: (minutes: number = 5): Promise<AxiosResponse<ApiResponse<any[]>>> => 
    api.get(`/anomalies/recent?minutes=${minutes}`),
  getCritical: (limit: number = 100): Promise<AxiosResponse<ApiResponse<any[]>>> => 
    api.get(`/anomalies?severity=CRITICAL&limit=${limit}`),
  getStats: (minutes: number = 60): Promise<AxiosResponse<ApiResponse<any>>> => 
    api.get(`/anomalies/stats?minutes=${minutes}`),
  getById: (id: string | number): Promise<AxiosResponse<ApiResponse<any>>> => 
    api.get(`/anomalies/${id}`),
};

// Flows API (replaces Traffic)
export const flowsAPI = {
  getAll: (params: QueryParams = {}): Promise<AxiosResponse<ApiResponse<any[]>>> => 
    api.get('/flows', { params }),
  getRecent: (minutes: number = 5): Promise<AxiosResponse<ApiResponse<any[]>>> => 
    api.get(`/flows/recent?minutes=${minutes}`),
  getStats: (minutes: number = 60): Promise<AxiosResponse<ApiResponse<any>>> => 
    api.get(`/flows/stats?minutes=${minutes}`),
  getById: (id: string | number): Promise<AxiosResponse<ApiResponse<any>>> => 
    api.get(`/flows/${id}`),
};

// Metrics API
export const metricsAPI = {
  getAll: (params: QueryParams = {}): Promise<AxiosResponse<ApiResponse<ModelMetrics[]>>> => 
    api.get('/metrics', { params }),
  getLatest: (modelName?: string): Promise<AxiosResponse<ApiResponse<ModelMetrics>>> => 
    api.get(`/metrics/latest${modelName ? `?model_name=${modelName}` : ''}`),
  compare: (): Promise<AxiosResponse<ApiResponse<ModelMetrics[]>>> => 
    api.get('/metrics/compare'),
};

// Health Check
export const healthAPI = {
  check: (): Promise<AxiosResponse<HealthStatus>> => 
    axios.get(`${API_BASE_URL}/health`),
};

// Admin API
export const adminAPI = {
  clearAll: (): Promise<AxiosResponse<any>> => 
    api.delete('/admin/clear-all?confirm=true'),
  clearAnomalies: (): Promise<AxiosResponse<any>> => 
    api.delete('/anomalies/clear?confirm=true'),
  clearFlows: (): Promise<AxiosResponse<any>> => 
    api.delete('/flows/clear?confirm=true'),
  getStats: (): Promise<AxiosResponse<any>> => 
    api.get('/admin/stats'),
};

export default api;
