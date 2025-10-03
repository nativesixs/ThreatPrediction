import { useState, useEffect } from 'react';
import {
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  Alert,
  CircularProgress,
} from '@mui/material';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';

import wsService from '@/services/websocket';
import { predictionsAPI, trafficAPI } from '@/services/api';
import type { Prediction } from '@/types';

const COLORS = ['#4caf50', '#ff1744', '#ff9800', '#2196f3', '#9c27b0'];

interface DashboardProps {
  wsConnected: boolean;
  setWsConnected: (connected: boolean) => void;
}

interface LiveDataPoint {
  time: string;
  confidence: number;
  isAttack: number;
}

interface AttackTypeData {
  name: string;
  value: number;
  [key: string]: string | number; // Index signature for Recharts compatibility
}

interface TrafficStats {
  total_packets?: number;
  protocols?: Record<string, number>;
  [key: string]: any;
}

const Dashboard: React.FC<DashboardProps> = ({ wsConnected, setWsConnected }) => {
  const [predictions, setPredictions] = useState<Prediction[]>([]);
  const [predictionStats, setPredictionStats] = useState<any>(null);
  const [trafficStats, setTrafficStats] = useState<TrafficStats | null>(null);
  const [recentAttacks, setRecentAttacks] = useState<any[]>([]);
  const [attacksByType, setAttacksByType] = useState<AttackTypeData[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [liveData, setLiveData] = useState<LiveDataPoint[]>([]);

  // Load settings from localStorage
  const getSettings = () => {
    try {
      const saved = localStorage.getItem('appSettings');
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
    return { refreshInterval: 30, maxRecentAttacks: 10 };
  };

  useEffect(() => {
    // Connect to WebSocket
    wsService.connect();

    // Subscribe to prediction updates
    const unsubscribePrediction = wsService.subscribe('prediction', (data) => {
      console.log('Received prediction:', data);
      
      // Add to live data for visualization
      setLiveData(prev => {
        const newData = [...prev, {
          time: new Date().toLocaleTimeString(),
          confidence: data.prediction?.confidence || 0,
          isAttack: data.prediction?.is_attack ? 1 : 0,
        }];
        return newData.slice(-20); // Keep last 20 data points
      });

      // Update stats in real-time
      setPredictionStats(prev => {
        if (!prev) return prev;
        return {
          ...prev,
          total_predictions: (prev.total_predictions || 0) + 1,
          total_packets: (prev.total_packets || 0) + 1,
          total_attacks: data.prediction?.is_attack 
            ? (prev.total_attacks || 0) + 1 
            : prev.total_attacks,
          benign_count: !data.prediction?.is_attack 
            ? (prev.benign_count || 0) + 1 
            : prev.benign_count,
        };
      });

      // Add to predictions list
      if (data.prediction?.is_attack) {
        const settings = getSettings();
        const maxAttacks = settings.maxRecentAttacks || 10;
        setRecentAttacks(prev => [data, ...prev].slice(0, maxAttacks));
      }
    });

    // Subscribe to connection status
    const unsubscribeConnection = wsService.subscribe('connection', (data) => {
      setWsConnected(data.status === 'connected');
    });

    // Subscribe to alerts
    const unsubscribeAlert = wsService.subscribe('alert', (data) => {
      console.log('Alert received:', data);
    });

    // Load initial data
    loadDashboardData();

    // Refresh data based on settings
    const settings = getSettings();
    const refreshMs = (settings.refreshInterval || 30) * 1000;
    const interval = setInterval(loadDashboardData, refreshMs);
    
    // Update stats more frequently (every 5 seconds) for real-time feel
    const statsInterval = setInterval(async () => {
      try {
        const predStatsResponse = await predictionsAPI.getStats(60);
        setPredictionStats(predStatsResponse.data);
      } catch (error) {
        console.error('Error updating stats:', error);
      }
    }, 5000);

    return () => {
      unsubscribePrediction();
      unsubscribeConnection();
      unsubscribeAlert();
      clearInterval(interval);
      clearInterval(statsInterval);
    };
  }, [setWsConnected]);

  const loadDashboardData = async (): Promise<void> => {
    try {
      setLoading(true);
      setError(null);
      
      // Get settings
      const settings = getSettings();
      const maxAttacks = settings.maxRecentAttacks || 10;

      // Load recent predictions
      const predsResponse = await predictionsAPI.getRecent(maxAttacks);
      const predsData = predsResponse.data.data || predsResponse.data;
      setPredictions(Array.isArray(predsData) ? predsData : []);

      // Load prediction stats
      const predStatsResponse = await predictionsAPI.getStats(60);
      setPredictionStats(predStatsResponse.data);

      // Load traffic stats
      const statsResponse = await trafficAPI.getStats(60);
      setTrafficStats(statsResponse.data.data || statsResponse.data);

      // Load recent attacks with details
      try {
        const attacksResponse = await predictionsAPI.getAttacksDetailed(maxAttacks);
        const attacksData = attacksResponse.data.data || attacksResponse.data;
        setRecentAttacks(Array.isArray(attacksData) ? attacksData : []);
      } catch (error) {
        // Fallback to regular attacks endpoint if detailed endpoint fails
        console.warn('Detailed attacks endpoint failed, using regular endpoint', error);
        const attacksResponse = await predictionsAPI.getAttacks(maxAttacks);
        const attacksData = attacksResponse.data.data || attacksResponse.data;
        setRecentAttacks(Array.isArray(attacksData) ? attacksData : []);
      }

      // Process attack types for pie chart
      const attackTypes: Record<string, number> = {};
      const predsArray = Array.isArray(predsData) ? predsData : [];
      predsArray.forEach((pred: Prediction) => {
        if (pred.is_attack) {
          const type = pred.predicted_class || 'Unknown';
          attackTypes[type] = (attackTypes[type] || 0) + 1;
        }
      });

      const attacksByTypeData: AttackTypeData[] = Object.entries(attackTypes).map(([name, value]) => ({
        name,
        value: value as number,
      }));
      setAttacksByType(attacksByTypeData);

    } catch (err) {
      console.error('Error loading dashboard data:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  if (loading && predictions.length === 0) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="60vh">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Real-Time Dashboard
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* @ts-expect-error - MUI v7 Grid type compatibility */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Predictions
              </Typography>
              <Typography variant="h4">
                {predictionStats?.total_predictions || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* @ts-expect-error - MUI v7 Grid type compatibility */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'error.dark' }}>
            <CardContent>
              <Typography color="white" gutterBottom>
                Attacks Detected
              </Typography>
              <Typography variant="h4" color="white">
                {predictionStats?.total_attacks || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* @ts-expect-error - MUI v7 Grid type compatibility */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Packets
              </Typography>
              <Typography variant="h4">
                {predictionStats?.total_packets || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* @ts-expect-error - MUI v7 Grid type compatibility */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: wsConnected ? 'success.dark' : 'grey.700' }}>
            <CardContent>
              <Typography color="white" gutterBottom>
                Connection Status
              </Typography>
              <Typography variant="h4" color="white">
                {wsConnected ? 'Live' : 'Offline'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        {/* Real-time Confidence Chart */}
        {/* @ts-expect-error - MUI v7 Grid type compatibility */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Real-Time Prediction Confidence
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={liveData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis domain={[0, 1]} />
                <Tooltip />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="confidence" 
                  stroke="#2196f3" 
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        {/* Attack Types Distribution */}
        {/* @ts-expect-error - MUI v7 Grid type compatibility */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Attack Types
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={attacksByType}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }: any) => `${name}: ${((percent as number) * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {attacksByType.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        {/* Protocol Distribution */}
        {trafficStats && (
          // @ts-expect-error - MUI v7 Grid type compatibility
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Protocol Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart
                  data={Object.entries(trafficStats.protocols || {}).map(([name, value]) => ({
                    name,
                    value,
                  }))}
                >
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" fill="#2196f3" />
                </BarChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        )}

        {/* Recent Attacks */}
        {/* @ts-expect-error - MUI v7 Grid type compatibility */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Recent Attack Predictions
            </Typography>
            <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
              {recentAttacks.length === 0 ? (
                <Typography color="textSecondary">No attacks detected</Typography>
              ) : (
                recentAttacks.map((attack, index) => {
                  const attackType = attack.prediction?.predicted_label || attack.predicted_class;
                  const confidence = (attack.prediction?.confidence || attack.confidence_score) * 100;
                  const packetInfo = attack.packet_info || {};
                  
                  return (
                    <Alert 
                      key={index} 
                      severity="error" 
                      sx={{ mb: 1 }}
                    >
                      <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                        {attackType} - {confidence.toFixed(1)}% confidence
                      </Typography>
                      <Typography variant="caption" component="div" sx={{ opacity: 0.9 }}>
                        {packetInfo.source_ip && (
                          <>Source: {packetInfo.source_ip}{packetInfo.source_port ? `:${packetInfo.source_port}` : ''}</>
                        )}
                      </Typography>
                      <Typography variant="caption" component="div" sx={{ opacity: 0.9 }}>
                        {packetInfo.destination_ip && (
                          <>Dest: {packetInfo.destination_ip}{packetInfo.destination_port ? `:${packetInfo.destination_port}` : ''}</>
                        )}
                      </Typography>
                      <Typography variant="caption" component="div" sx={{ opacity: 0.8 }}>
                        {packetInfo.protocol && `Protocol: ${packetInfo.protocol}`}
                        {packetInfo.packet_length && ` | Size: ${packetInfo.packet_length} bytes`}
                      </Typography>
                      {attack.timestamp && (
                        <Typography variant="caption" component="div" sx={{ opacity: 0.7, mt: 0.5 }}>
                          {new Date(attack.timestamp).toLocaleString()}
                        </Typography>
                      )}
                    </Alert>
                  );
                })
              )}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard;
