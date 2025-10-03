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
import { predictionsAPI } from '@/services/api';

const PredictionsPage: React.FC = () => {
  const [predictions, setPredictions] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [page, setPage] = useState<number>(0);
  const [rowsPerPage, setRowsPerPage] = useState<number>(25);
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    loadPredictions();
  }, [filter, page, rowsPerPage]);

  const loadPredictions = async () => {
    try {
      setLoading(true);
      const params: any = {
        limit: rowsPerPage,
        skip: page * rowsPerPage,
      };

      if (filter !== 'all') {
        params.is_attack = filter === 'attacks';
      }

      const response = await predictionsAPI.getAll(params);
      const data = (response.data as any).data || response.data || [];
      setPredictions(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error loading predictions:', error);
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
        Prediction History
      </Typography>

      <Box sx={{ mb: 2 }}>
        <TextField
          select
          label="Filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          sx={{ minWidth: 200 }}
        >
          <MenuItem value="all">All Predictions</MenuItem>
          <MenuItem value="attacks">Attacks Only</MenuItem>
          <MenuItem value="benign">Benign Only</MenuItem>
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
                <TableCell>Model</TableCell>
                <TableCell>Prediction</TableCell>
                <TableCell>Confidence</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Processing Time</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {predictions.map((pred) => (
                <TableRow key={pred.id}>
                  <TableCell>
                    {new Date(pred.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>{pred.model_name}</TableCell>
                  <TableCell>{pred.predicted_class}</TableCell>
                  <TableCell>
                    {(pred.confidence_score * 100).toFixed(2)}%
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={pred.is_attack ? 'Attack' : 'Benign'}
                      color={pred.is_attack ? 'error' : 'success'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    {pred.processing_time_ms 
                      ? `${pred.processing_time_ms.toFixed(2)}ms`
                      : 'N/A'}
                  </TableCell>
                </TableRow>
              ))}
              {predictions.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    No predictions found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={-1}
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
