/// <reference types="vite/client" />

import axios, { AxiosResponse } from 'axios';
import type { 
  Prediction, 
  TrafficLog, 
  ModelMetrics, 
  ApiResponse, 
  HealthStatus 
} from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const API_PREFIX = '/api/v1';

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

// Predictions API
export const predictionsAPI = {
  getAll: (params: QueryParams = {}): Promise<AxiosResponse<ApiResponse<Prediction[]>>> => 
    api.get('/predictions', { params }),
  getRecent: (minutes: number = 5): Promise<AxiosResponse<ApiResponse<Prediction[]>>> => 
    api.get(`/predictions/recent?minutes=${minutes}`),
  getAttacks: (limit: number = 100): Promise<AxiosResponse<ApiResponse<Prediction[]>>> => 
    api.get(`/predictions/attacks?limit=${limit}`),
  getAttacksDetailed: (limit: number = 100): Promise<AxiosResponse<ApiResponse<any[]>>> => 
    api.get(`/predictions/attacks/detailed?limit=${limit}`),
  getStats: (minutes: number = 60): Promise<AxiosResponse<ApiResponse<any>>> => 
    api.get(`/predictions/stats?minutes=${minutes}`),
  getById: (id: string | number): Promise<AxiosResponse<ApiResponse<Prediction>>> => 
    api.get(`/predictions/${id}`),
};

// Traffic API
export const trafficAPI = {
  getAll: (params: QueryParams = {}): Promise<AxiosResponse<ApiResponse<TrafficLog[]>>> => 
    api.get('/traffic', { params }),
  getRecent: (minutes: number = 5): Promise<AxiosResponse<ApiResponse<TrafficLog[]>>> => 
    api.get(`/traffic/recent?minutes=${minutes}`),
  getStats: (minutes: number = 60): Promise<AxiosResponse<ApiResponse<any>>> => 
    api.get(`/traffic/stats?minutes=${minutes}`),
  getById: (id: string | number): Promise<AxiosResponse<ApiResponse<TrafficLog>>> => 
    api.get(`/traffic/${id}`),
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
  clearPredictions: (): Promise<AxiosResponse<any>> => 
    api.delete('/predictions/clear?confirm=true'),
  clearTraffic: (): Promise<AxiosResponse<any>> => 
    api.delete('/traffic/clear?confirm=true'),
  getStats: (): Promise<AxiosResponse<any>> => 
    api.get('/admin/stats'),
};

export default api;
