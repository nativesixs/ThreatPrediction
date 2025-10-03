/// <reference types="vite/client" />

type MessageType = 'prediction' | 'alert' | 'stats' | 'connection' | 'error' | 'heartbeat' | 'pong';
type Listener = (data: any) => void;
type Listeners = Record<MessageType, Listener[]>;

interface WebSocketMessage {
  type: MessageType;
  data?: any;
  timestamp?: string;
}

class WebSocketService {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectInterval: number = 3000;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private isIntentionalClose: boolean = false;
  private listeners: Listeners;

  constructor() {
    this.url = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws';
    this.listeners = {
      prediction: [],
      alert: [],
      stats: [],
      connection: [],
      error: [],
      heartbeat: [],
      pong: [],
    };
  }

  connect(): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected');
      return;
    }

    console.log('Connecting to WebSocket:', this.url);
    this.isIntentionalClose = false;

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.notifyListeners('connection', { status: 'connected' });
        
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
          this.reconnectTimer = null;
        }

        this.startHeartbeat();
      };

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          console.log('WebSocket message:', message.type);
          
          const { type, data } = message;
          
          if (type && this.listeners[type]) {
            this.notifyListeners(type, data);
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      this.ws.onerror = (error: Event) => {
        console.error('WebSocket error:', error);
        this.notifyListeners('error', error);
      };

      this.ws.onclose = (event: CloseEvent) => {
        console.log('WebSocket closed:', event.code, event.reason);
        this.notifyListeners('connection', { status: 'disconnected' });
        this.stopHeartbeat();

        if (!this.isIntentionalClose) {
          console.log(`Reconnecting in ${this.reconnectInterval}ms...`);
          this.reconnectTimer = setTimeout(() => {
            this.connect();
          }, this.reconnectInterval);
        }
      };
    } catch (error) {
      console.error('Error creating WebSocket:', error);
      this.notifyListeners('error', error);
    }
  }

  disconnect(): void {
    this.isIntentionalClose = true;
    this.stopHeartbeat();
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  send(message: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket not connected, cannot send message');
    }
  }

  subscribe(type: MessageType, callback: Listener): () => void {
    if (this.listeners[type]) {
      this.listeners[type].push(callback);
      
      return () => {
        this.listeners[type] = this.listeners[type].filter((cb) => cb !== callback);
      };
    }
    return () => {};
  }

  private notifyListeners(type: MessageType, data: any): void {
    if (this.listeners[type]) {
      this.listeners[type].forEach((callback) => {
        try {
          callback(data);
        } catch (error) {
          console.error(`Error in ${type} listener:`, error);
        }
      });
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.send({ type: 'ping' });
      }
    }, 30000);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }
}

const wsService = new WebSocketService();

export default wsService;
