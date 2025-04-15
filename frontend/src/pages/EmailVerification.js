import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  TextField,
  Button,
  Paper,
  Alert,
  CircularProgress
} from '@mui/material';
import axios from 'axios';
import { useNavigate, useLocation } from 'react-router-dom';

const EmailVerification = () => {
  const [otp, setOtp] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const userId = location.state?.userId;

  const handleVerify = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await axios.post('/api/auth/verify-email', {
        userId,
        otp
      });

      if (response.data.success) {
        // Store token and user data
        localStorage.setItem('token', response.data.token);
        localStorage.setItem('user', JSON.stringify(response.data.user));
        
        // Redirect based on role
        if (response.data.user.role === 'admin') {
          navigate('/admin-dashboard');
        } else {
          navigate('/dashboard');
        }
      }
    } catch (error) {
      setError(error.response?.data?.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleResendOTP = async () => {
    setError('');
    setLoading(true);

    try {
      const response = await axios.post('/api/auth/resend-otp', {
        userId
      });

      if (response.data.success) {
        setError('New OTP sent to your email');
      }
    } catch (error) {
      setError(error.response?.data?.message || 'Failed to resend OTP');
    } finally {
      setLoading(false);
    }
  };

  if (!userId) {
    navigate('/login');
    return null;
  }

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8, mb: 4 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom align="center">
            Email Verification
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3 }} align="center">
            Please enter the 6-digit OTP sent to your email
          </Typography>

          {error && (
            <Alert severity={error.includes('sent') ? 'success' : 'error'} sx={{ mb: 3 }}>
              {error}
            </Alert>
          )}

          <form onSubmit={handleVerify}>
            <TextField
              fullWidth
              label="Enter OTP"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              margin="normal"
              inputProps={{
                maxLength: 6,
                inputMode: 'numeric',
                pattern: '[0-9]*'
              }}
              disabled={loading}
            />

            <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
              <Button
                fullWidth
                variant="contained"
                color="primary"
                type="submit"
                disabled={loading || otp.length !== 6}
              >
                {loading ? <CircularProgress size={24} /> : 'Verify OTP'}
              </Button>

              <Button
                fullWidth
                variant="outlined"
                onClick={handleResendOTP}
                disabled={loading}
              >
                Resend OTP
              </Button>
            </Box>
          </form>
        </Paper>
      </Box>
    </Container>
  );
};

export default EmailVerification;
