import { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  Box,
  CircularProgress,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { metricsAPI } from '@/services/api';

const MetricsPage: React.FC = () => {
  const [metrics, setMetrics] = useState<any[]>([]);
  const [comparison, setComparison] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    loadMetrics();
  }, []);

  const loadMetrics = async () => {
    try {
      setLoading(true);
      
      const [metricsResponse, comparisonResponse] = await Promise.all([
        metricsAPI.getAll({ limit: 10 }),
        metricsAPI.compare(),
      ]);

      setMetrics((metricsResponse.data as any).data || metricsResponse.data || []);
      setComparison((comparisonResponse.data as any).data || comparisonResponse.data || null);
    } catch (error) {
      console.error('Error loading metrics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="60vh">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Model Performance Metrics
      </Typography>

      {/* Model Comparison */}
      {comparison && comparison.models && (
        <>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {/* @ts-expect-error - MUI v7 Grid type compatibility */}
            <Grid item xs={12} sm={6}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Best Accuracy
                  </Typography>
                  <Typography variant="h4">
                    {(comparison.best_accuracy * 100).toFixed(2)}%
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            {/* @ts-expect-error - MUI v7 Grid type compatibility */}
            <Grid item xs={12} sm={6}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Best F1 Score
                  </Typography>
                  <Typography variant="h4">
                    {(comparison.best_f1 * 100).toFixed(2)}%
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Comparison Chart */}
          <Paper sx={{ p: 2, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Model Comparison
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={comparison.models}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="model_name" />
                <YAxis domain={[0, 1]} />
                <Tooltip />
                <Legend />
                <Bar dataKey="accuracy" fill="#2196f3" name="Accuracy" />
                <Bar dataKey="precision" fill="#4caf50" name="Precision" />
                <Bar dataKey="recall" fill="#ff9800" name="Recall" />
                <Bar dataKey="f1_score" fill="#9c27b0" name="F1 Score" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </>
      )}

      {/* Detailed Metrics Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Model</TableCell>
              <TableCell>Accuracy</TableCell>
              <TableCell>Precision</TableCell>
              <TableCell>Recall</TableCell>
              <TableCell>F1 Score</TableCell>
              <TableCell>Timestamp</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {metrics.map((metric) => (
              <TableRow key={metric.id}>
                <TableCell>{metric.model_name}</TableCell>
                <TableCell>
                  {metric.accuracy ? (metric.accuracy * 100).toFixed(2) + '%' : 'N/A'}
                </TableCell>
                <TableCell>
                  {metric.precision ? (metric.precision * 100).toFixed(2) + '%' : 'N/A'}
                </TableCell>
                <TableCell>
                  {metric.recall ? (metric.recall * 100).toFixed(2) + '%' : 'N/A'}
                </TableCell>
                <TableCell>
                  {metric.f1_score ? (metric.f1_score * 100).toFixed(2) + '%' : 'N/A'}
                </TableCell>
                <TableCell>
                  {new Date(metric.timestamp).toLocaleString()}
                </TableCell>
              </TableRow>
            ))}
            {metrics.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  No metrics found
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

export default MetricsPage;
