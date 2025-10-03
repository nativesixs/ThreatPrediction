import { useEffect, useState, useCallback, useRef } from 'react';
import wsService from '@/services/websocket';
import type { WebSocketMessage, PredictionMessage } from '@/types';

interface UseWebSocketReturn {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  predictions: PredictionMessage[];
  sendMessage: (message: any) => void;
  connect: () => void;
  disconnect: () => void;
}

export const useWebSocket = (): UseWebSocketReturn => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [predictions, setPredictions] = useState<PredictionMessage[]>([]);
  const predictionsRef = useRef<PredictionMessage[]>([]);

  useEffect(() => {
    // Subscribe to connection status
    const unsubConnection = wsService.subscribe('connection', (data) => {
      setIsConnected(data.status === 'connected');
    });

    // Subscribe to all message types
    const unsubPrediction = wsService.subscribe('prediction', (data) => {
      const newPrediction = data as PredictionMessage;
      setPredictions((prev) => {
        const updated = [newPrediction, ...prev].slice(0, 50);
        predictionsRef.current = updated;
        return updated;
      });
      setLastMessage({ type: 'prediction', data, timestamp: new Date().toISOString() });
    });

    const unsubAlert = wsService.subscribe('alert', (data) => {
      setLastMessage({ type: 'alert', data, timestamp: new Date().toISOString() });
    });

    const unsubStats = wsService.subscribe('stats', (data) => {
      setLastMessage({ type: 'stats', data, timestamp: new Date().toISOString() });
    });

    const unsubError = wsService.subscribe('error', (data) => {
      setLastMessage({ type: 'error', data, timestamp: new Date().toISOString() });
    });

    // Auto-connect
    wsService.connect();

    return () => {
      unsubConnection();
      unsubPrediction();
      unsubAlert();
      unsubStats();
      unsubError();
    };
  }, []);

  const sendMessage = useCallback((message: any) => {
    wsService.send(message);
  }, []);

  const connect = useCallback(() => {
    wsService.connect();
  }, []);

  const disconnect = useCallback(() => {
    wsService.disconnect();
  }, []);

  return {
    isConnected,
    lastMessage,
    predictions,
    sendMessage,
    connect,
    disconnect,
  };
};
