import { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  Box,
  TextField,
  MenuItem,
  CircularProgress,
} from '@mui/material';
import { anomaliesAPI } from '@/services/api';
import type { Anomaly } from '@/types';

const PredictionsPage: React.FC = () => {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [page, setPage] = useState<number>(0);
  const [rowsPerPage, setRowsPerPage] = useState<number>(25);
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    loadAnomalies();
  }, [filter, page, rowsPerPage]);

  const loadAnomalies = async () => {
    try {
      setLoading(true);
      const params: any = {
        limit: rowsPerPage,
        skip: page * rowsPerPage,
      };

      if (filter === 'attacks') {
        params.severity = 'CRITICAL';
      }

      const response = await anomaliesAPI.getAll(params);
      const data = (response.data as any).data || response.data || [];
      setAnomalies(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error loading anomalies:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Anomaly History
      </Typography>

      <Box sx={{ mb: 2 }}>
        <TextField
          select
          label="Filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          sx={{ minWidth: 200 }}
        >
          <MenuItem value="all">All Anomalies</MenuItem>
          <MenuItem value="attacks">Critical Only</MenuItem>
        </TextField>
      </Box>

      {loading ? (
        <Box display="flex" justifyContent="center" p={4}>
          <CircularProgress />
        </Box>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Reconstruction Error</TableCell>
                <TableCell>Anomaly Score</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Type</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {anomalies.map((anomaly) => (
                <TableRow key={anomaly.id}>
                  <TableCell>
                    {new Date(anomaly.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>{anomaly.reconstruction_error.toFixed(4)}</TableCell>
                  <TableCell>{anomaly.anomaly_score.toFixed(4)}</TableCell>
                  <TableCell>
                    <Chip
                      label={anomaly.severity}
                      color={anomaly.severity === 'CRITICAL' ? 'error' : anomaly.severity === 'HIGH' ? 'warning' : 'primary'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    {anomaly.is_anomaly ? 'Anomaly' : 'Normal'}
                  </TableCell>
                </TableRow>
              ))}
              {anomalies.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    No anomalies found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={anomalies.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </TableContainer>
      )}
    </Box>
  );
}

export default PredictionsPage;
