import { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  Box,
  TextField,
  Button,
  Grid,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  CircularProgress,
} from '@mui/material';
import { adminAPI } from '@/services/api';

const SettingsPage: React.FC = () => {
  // Default settings
  const defaultSettings = {
    apiUrl: import.meta.env.VITE_API_URL || 'http://localhost:8000',
    wsUrl: import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws',
    refreshInterval: 30,
    maxRecentAttacks: 10,
    enableNotifications: true,
    enableAutoReconnect: true,
  };

  // Load settings from localStorage or use defaults
  const loadSettings = () => {
    try {
      const saved = localStorage.getItem('appSettings');
      if (saved) {
        return { ...defaultSettings, ...JSON.parse(saved) };
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
    return defaultSettings;
  };

  const [settings, setSettings] = useState(loadSettings());

  // Load settings on mount
  useEffect(() => {
    setSettings(loadSettings());
  }, []);

  const [saved, setSaved] = useState<boolean>(false);
  const [clearDialog, setClearDialog] = useState<{
    open: boolean;
    type: 'all' | 'predictions' | 'traffic' | null;
  }>({ open: false, type: null });
  const [clearing, setClearing] = useState<boolean>(false);
  const [clearSuccess, setClearSuccess] = useState<string | null>(null);
  const [clearError, setClearError] = useState<string | null>(null);

  const handleChange = (field: string) => (event: any): void => {
    const value = event.target.type === 'checkbox' 
      ? event.target.checked 
      : event.target.value;
    
    setSettings(prev => ({
      ...prev,
      [field]: value,
    }));
    setSaved(false);
  };

  const handleSave = (): void => {
    // Save to localStorage
    localStorage.setItem('appSettings', JSON.stringify(settings));
    setSaved(true);
    
    setTimeout(() => setSaved(false), 3000);
  };

  const handleReset = (): void => {
    // Remove from localStorage and reset to defaults
    localStorage.removeItem('appSettings');
    setSettings(defaultSettings);
    setSaved(false);
  };

  const handleClearData = async (): Promise<void> => {
    if (!clearDialog.type) return;

    setClearing(true);
    setClearError(null);
    setClearSuccess(null);

    try {
      let response;
      switch (clearDialog.type) {
        case 'all':
          response = await adminAPI.clearAll();
          break;
        case 'predictions':
          response = await adminAPI.clearPredictions();
          break;
        case 'traffic':
          response = await adminAPI.clearTraffic();
          break;
      }

      const message = response.data.message || 'Data cleared successfully';
      setClearSuccess(message);
      
      // Close dialog after success
      setTimeout(() => {
        setClearDialog({ open: false, type: null });
        setClearSuccess(null);
      }, 2000);
    } catch (error: any) {
      console.error('Error clearing data:', error);
      const errorMsg = error.response?.data?.detail || 'Failed to clear data';
      setClearError(errorMsg);
    } finally {
      setClearing(false);
    }
  };

  const openClearDialog = (type: 'all' | 'predictions' | 'traffic'): void => {
    setClearDialog({ open: true, type });
  };

  const closeClearDialog = (): void => {
    if (!clearing) {
      setClearDialog({ open: false, type: null });
      setClearError(null);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Settings
      </Typography>

      {saved && (
        <Alert severity="success" sx={{ mb: 2 }}>
          Settings saved successfully!
        </Alert>
      )}

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Connection Settings
        </Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {/* @ts-expect-error - MUI v7 Grid type compatibility */}
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="API URL"
              value={settings.apiUrl}
              onChange={handleChange('apiUrl')}
              helperText="Backend API endpoint"
            />
          </Grid>
          {/* @ts-expect-error - MUI v7 Grid type compatibility */}
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="WebSocket URL"
              value={settings.wsUrl}
              onChange={handleChange('wsUrl')}
              helperText="WebSocket endpoint for real-time updates"
            />
          </Grid>
        </Grid>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" gutterBottom>
          Dashboard Settings
        </Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {/* @ts-expect-error - MUI v7 Grid type compatibility */}
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              type="number"
              label="Refresh Interval (seconds)"
              value={settings.refreshInterval}
              onChange={handleChange('refreshInterval')}
              helperText="How often to refresh dashboard data"
            />
          </Grid>
          {/* @ts-expect-error - MUI v7 Grid type compatibility */}
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              type="number"
              label="Max Recent Attacks"
              value={settings.maxRecentAttacks}
              onChange={handleChange('maxRecentAttacks')}
              helperText="Number of recent attacks to display"
            />
          </Grid>
        </Grid>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" gutterBottom>
          Notifications
        </Typography>
        <Box sx={{ mb: 3 }}>
          <FormControlLabel
            control={
              <Switch
                checked={settings.enableNotifications}
                onChange={handleChange('enableNotifications')}
              />
            }
            label="Enable Desktop Notifications"
          />
          <Typography variant="caption" display="block" color="textSecondary">
            Receive browser notifications for new attacks
          </Typography>
        </Box>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" gutterBottom>
          WebSocket
        </Typography>
        <Box sx={{ mb: 3 }}>
          <FormControlLabel
            control={
              <Switch
                checked={settings.enableAutoReconnect}
                onChange={handleChange('enableAutoReconnect')}
              />
            }
            label="Enable Auto-Reconnect"
          />
          <Typography variant="caption" display="block" color="textSecondary">
            Automatically reconnect to WebSocket if connection is lost
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button variant="contained" onClick={handleSave}>
            Save Settings
          </Button>
          <Button variant="outlined" onClick={handleReset}>
            Reset to Defaults
          </Button>
        </Box>
      </Paper>

      {/* Data Management Section */}
      <Paper sx={{ p: 3, mt: 3 }}>
        <Typography variant="h6" gutterBottom color="error">
          Data Management
        </Typography>
        <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
          Clear stored data from the database. This action cannot be undone!
        </Typography>

        {clearSuccess && (
          <Alert severity="success" sx={{ mb: 2 }}>
            {clearSuccess}
          </Alert>
        )}

        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <Button 
            variant="outlined" 
            color="warning"
            onClick={() => openClearDialog('predictions')}
          >
            Clear Predictions
          </Button>
          <Button 
            variant="outlined" 
            color="warning"
            onClick={() => openClearDialog('traffic')}
          >
            Clear Traffic Logs
          </Button>
          <Button 
            variant="contained" 
            color="error"
            onClick={() => openClearDialog('all')}
          >
            Clear All Data
          </Button>
        </Box>
      </Paper>

      {/* Confirmation Dialog */}
      <Dialog open={clearDialog.open} onClose={closeClearDialog}>
        <DialogTitle>
          Confirm Data Deletion
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {clearDialog.type === 'all' && (
              <>
                Are you sure you want to delete <strong>ALL data</strong> including predictions and traffic logs?
                <br /><br />
                <strong>This action cannot be undone!</strong>
              </>
            )}
            {clearDialog.type === 'predictions' && (
              <>
                Are you sure you want to delete all <strong>prediction data</strong>?
                <br /><br />
                This will remove all stored predictions from the database.
              </>
            )}
            {clearDialog.type === 'traffic' && (
              <>
                Are you sure you want to delete all <strong>traffic logs</strong>?
                <br /><br />
                This will remove all stored network traffic data from the database.
              </>
            )}
          </DialogContentText>
          
          {clearError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {clearError}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeClearDialog} disabled={clearing}>
            Cancel
          </Button>
          <Button 
            onClick={handleClearData} 
            color="error" 
            variant="contained"
            disabled={clearing}
            startIcon={clearing ? <CircularProgress size={20} /> : null}
          >
            {clearing ? 'Clearing...' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default SettingsPage;
