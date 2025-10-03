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
import { trafficAPI } from '@/services/api';

const TrafficPage: React.FC = () => {
  const [traffic, setTraffic] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [page, setPage] = useState<number>(0);
  const [rowsPerPage, setRowsPerPage] = useState<number>(25);

  useEffect(() => {
    loadTrafficData();
  }, [page, rowsPerPage]);

  const loadTrafficData = async () => {
    try {
      setLoading(true);
      
      const [trafficResponse, statsResponse] = await Promise.all([
        trafficAPI.getAll({
          limit: rowsPerPage,
          skip: page * rowsPerPage,
        }),
        trafficAPI.getStats(60),
      ]);

      setTraffic((trafficResponse.data as any).data || trafficResponse.data || []);
      setStats((statsResponse.data as any).data || statsResponse.data || null);
    } catch (error) {
      console.error('Error loading traffic data:', error);
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
              {traffic.map((log) => (
                <TableRow key={log.id}>
                  <TableCell>
                    {new Date(log.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>{log.source_ip}</TableCell>
                  <TableCell>{log.destination_ip}</TableCell>
                  <TableCell>{log.protocol}</TableCell>
                  <TableCell>{log.source_port}</TableCell>
                  <TableCell>{log.destination_port}</TableCell>
                  <TableCell>{log.packet_length}</TableCell>
                </TableRow>
              ))}
              {traffic.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    No traffic data found
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

export default TrafficPage;
