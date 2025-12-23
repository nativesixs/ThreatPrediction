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
  Box,
  CircularProgress,
  Grid,
  Card,
  CardContent,
} from '@mui/material';
import { flowsAPI } from '@/services/api';

const TrafficPage: React.FC = () => {
  const [flows, setFlows] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [page, setPage] = useState<number>(0);
  const [rowsPerPage, setRowsPerPage] = useState<number>(25);

  useEffect(() => {
    loadFlowData();
  }, [page, rowsPerPage]);

  const loadFlowData = async () => {
    try {
      setLoading(true);
      
      const [flowsResponse, statsResponse] = await Promise.all([
        flowsAPI.getAll({
          limit: rowsPerPage,
          skip: page * rowsPerPage,
        }),
        flowsAPI.getStats(60),
      ]);

      setFlows((flowsResponse.data as any).data || flowsResponse.data || []);
      setStats((statsResponse.data as any).data || statsResponse.data || null);
    } catch (error) {
      console.error('Error loading flow data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleChangePage = (_event: unknown, newPage: number): void => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>): void => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Network Traffic
      </Typography>

      {/* Statistics Cards */}
      {stats && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {/* @ts-expect-error - MUI v7 Grid type compatibility */}
          <Grid item xs={12} sm={4}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total Packets (Last Hour)
                </Typography>
                <Typography variant="h4">
                  {stats.total_packets}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          {/* @ts-expect-error - MUI v7 Grid type compatibility */}
          <Grid item xs={12} sm={4}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Unique Source IPs
                </Typography>
                <Typography variant="h4">
                  {stats.top_sources?.length || 0}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          {/* @ts-expect-error - MUI v7 Grid type compatibility */}
          <Grid item xs={12} sm={4}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Unique Dest IPs
                </Typography>
                <Typography variant="h4">
                  {stats.top_destinations?.length || 0}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

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
                <TableCell>Source IP</TableCell>
                <TableCell>Destination IP</TableCell>
                <TableCell>Protocol</TableCell>
                <TableCell>Source Port</TableCell>
                <TableCell>Dest Port</TableCell>
                <TableCell>Packet Length</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {flows.map((flow) => (
                <TableRow key={flow.id}>
                  <TableCell>
                    {new Date(flow.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>{flow.source_ip}</TableCell>
                  <TableCell>{flow.destination_ip}</TableCell>
                  <TableCell>{flow.source_port || 'N/A'}</TableCell>
                  <TableCell>{flow.destination_port || 'N/A'}</TableCell>
                  <TableCell>{flow.protocol}</TableCell>
                  <TableCell>{flow.packet_length || 0}</TableCell>
                </TableRow>
              ))}
              {flows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    No flow data found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={flows.length}
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

export default TrafficPage;
