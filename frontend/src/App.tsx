import { useState } from 'react';
import { Box, Container, CssBaseline, ThemeProvider, createTheme } from '@mui/material';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import Navbar from '@/components/Navbar';
import Sidebar from '@/components/Sidebar';
import Dashboard from '@/pages/Dashboard';
import PredictionsPage from '@/pages/PredictionsPage';
import TrafficPage from '@/pages/TrafficPage';
import MetricsPage from '@/pages/MetricsPage';
import SettingsPage from '@/pages/SettingsPage';

// Create dark theme for security dashboard aesthetic
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#2196f3',
    },
    secondary: {
      main: '#f50057',
    },
    error: {
      main: '#ff1744',
    },
    warning: {
      main: '#ff9800',
    },
    success: {
      main: '#4caf50',
    },
    background: {
      default: '#0a1929',
      paper: '#132f4c',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
  },
});

const App: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(true);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  const toggleSidebar = (): void => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <Box sx={{ display: 'flex', minHeight: '100vh' }}>
          <Navbar 
            onMenuClick={toggleSidebar} 
            wsConnected={wsConnected}
          />
          <Sidebar open={sidebarOpen} />
          <Box
            component="main"
            sx={{
              flexGrow: 1,
              p: 3,
              mt: 8,
              ml: sidebarOpen ? '240px' : 0,
              transition: 'margin 0.3s',
              width: sidebarOpen ? 'calc(100% - 240px)' : '100%',
            }}
          >
            <Container maxWidth="xl">
              <Routes>
                <Route 
                  path="/" 
                  element={
                    <Dashboard 
                      wsConnected={wsConnected}
                      setWsConnected={setWsConnected}
                    />
                  } 
                />
                <Route path="/predictions" element={<PredictionsPage />} />
                <Route path="/traffic" element={<TrafficPage />} />
                <Route path="/metrics" element={<MetricsPage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Routes>
            </Container>
          </Box>
        </Box>
      </Router>
    </ThemeProvider>
  );
};

export default App;
