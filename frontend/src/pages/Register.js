import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  Alert,
  MenuItem,
  CircularProgress
} from '@mui/material';
import { useAuth } from '../context/AuthContext';

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    role: 'faculty',
    school: '',
    phone: ''
  });

  const [showOTPInput, setShowOTPInput] = useState(false);
  const [otp, setOtp] = useState('');
  const [registrationEmail, setRegistrationEmail] = useState('');
  const [errors, setErrors] = useState({
    phone: '',
    email: '',
    form: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { register } = useAuth();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
    
    // Validate phone number for Indian format
    if (name === 'phone') {
      if (!/^[6-9]\d{9}$/.test(value)) {
        setErrors(prev => ({
          ...prev,
          phone: ''
        }));
      } else {
        setErrors(prev => ({ ...prev, phone: '' }));
      }
    }

    // Validate Woxsen email
    if (name === 'email') {
      if (!value.endsWith('@woxsen.edu.in')) {
        setErrors(prev => ({
          ...prev,
          email: 'Please use your Woxsen email address (@woxsen.edu.in)'
        }));
      } else {
        setErrors(prev => ({ ...prev, email: '' }));
      }
    }
  };

  const handleOTPSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    if (!/^\d{6}$/.test(otp)) {
      setError('Please enter a valid 6-digit OTP');
      setLoading(false);
      return;
    }

    const verificationData = {
      email: registrationEmail.toLowerCase().trim(),
      otp: otp.trim()
    };

    console.log('Sending verification request:', verificationData);

    try {
      const response = await axios.post(
        'http://localhost:5000/api/auth/verify-email',
        verificationData,
        { headers: { 'Content-Type': 'application/json' } }
      );
      
      console.log('Verification response:', response.data);

      if (response.data.success) {
        // Store token and user data
        localStorage.setItem('token', response.data.token);
        localStorage.setItem('user', JSON.stringify(response.data.user));

        // Show success message
        setErrors(prev => ({ ...prev, form: 'Registration successful! Redirecting...' }));

        // Redirect after a short delay
        setTimeout(() => {
          if (response.data.user.role === 'admin') {
            navigate('/admin-dashboard');
          } else {
            navigate('/dashboard');
          }
        }, 1500);
      } else {
        setError(response.data.message || 'Verification failed');
      }
    } catch (error) {
      console.error('OTP verification error:', error);
      console.error('Error details:', {
        status: error.response?.status,
        message: error.response?.data?.message,
        error: error.message
      });
      
      if (error.response?.data?.message) {
        setError(error.response.data.message);
      } else if (error.message) {
        setError(error.message);
      } else {
        setError('Verification failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    console.log('Submitting registration:', formData);
    e.preventDefault();
    setLoading(true);
    setErrors({ phone: '', email: '', form: '' });

    // Validate before submission
    if (!formData.email.endsWith('@woxsen.edu.in')) {
      setErrors(prev => ({ ...prev, form: 'Please use your Woxsen email address' }));
      setLoading(false);
      return;
    }

    if (!/^[6-9]\d{9}$/.test(formData.phone)) {
      setErrors(prev => ({ ...prev, form: 'Please enter a valid Indian phone number' }));
      setLoading(false);
      return;
    }

    try {
      const response = await axios.post('http://localhost:5000/api/auth/register', formData);
      console.log('Registration response:', response.data);

      if (response.data.success) {
        setRegistrationEmail(formData.email);
        setShowOTPInput(true);
        setError('');
      }
    } catch (error) {
      console.error('Registration error:', error);
      setErrors(prev => ({ 
        ...prev, 
        form: error.response?.data?.message || 'Registration failed. Please try again.'
      }));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8, mb: 4 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Typography variant="h4" align="center" gutterBottom>
            Register
          </Typography>
          {(errors.form || error) && (
            <Alert severity={errors.form?.includes('successful') ? 'success' : 'error'} sx={{ mb: 2 }}>
              {errors.form || error}
            </Alert>
          )}
          {!showOTPInput ? (
            <form onSubmit={handleSubmit}>
              <TextField
                fullWidth
                label="Name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                margin="normal"
                required
              />
              <TextField
                fullWidth
                label="Email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleChange}
                margin="normal"
                required
                error={Boolean(errors.email)}
                helperText={errors.email || ''}
              />
              <TextField
                fullWidth
                label="Password"
                name="password"
                type="password"
                value={formData.password}
                onChange={handleChange}
                margin="normal"
                required
              />
              <TextField
                fullWidth
                select
                label="Role"
                name="role"
                value={formData.role}
                onChange={handleChange}
                margin="normal"
                required
              >
                <MenuItem value="student">Student</MenuItem>
                <MenuItem value="faculty">Faculty</MenuItem>
              </TextField>
              <TextField
                fullWidth
                select
                label="School"
                name="school"
                value={formData.school}
                onChange={handleChange}
                margin="normal"
                required
              >
                <MenuItem value="School of Business">School of Business</MenuItem>
                <MenuItem value="School of Technology">School of Technology</MenuItem>
                <MenuItem value="School of Arts and Design">School of Arts and Design</MenuItem>
                <MenuItem value="School of Architecture">School of Architecture</MenuItem>
                <MenuItem value="School of Law">School of Law</MenuItem>
                <MenuItem value="School of Liberal Arts and Sciences">School of Liberal Arts and Sciences</MenuItem>
              </TextField>
              <TextField
                fullWidth
                label="Phone"
                name="phone"
                value={formData.phone}
                onChange={handleChange}
                margin="normal"
                required
                error={Boolean(errors.phone)}
                helperText={errors.phone || ''}
                inputProps={{
                  maxLength: 10,
                  pattern: '[6-9][0-9]{9}'
                }}
              />
              <Button
                type="submit"
                fullWidth
                variant="contained"
                color="primary"
                disabled={loading}
                sx={{ mt: 3 }}
              >
                {loading ? <CircularProgress size={24} /> : 'Register'}
              </Button>
            </form>
          ) : (
            <form onSubmit={handleOTPSubmit}>
              <Typography variant="h6" gutterBottom>
                Email Verification
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Please enter the 6-digit OTP sent to your email <strong>{registrationEmail}</strong>
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Didn't receive the OTP? Check your spam folder or click the button below to go back and try again.
              </Typography>
              <TextField
                fullWidth
                label="Enter OTP"
                value={otp}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, '').slice(0, 6);
                  setOtp(value);
                }}
                margin="normal"
                required
                inputProps={{
                  maxLength: 6,
                  inputMode: 'numeric',
                  pattern: '[0-9]*'
                }}
              />
              <Button
                type="submit"
                fullWidth
                variant="contained"
                color="primary"
                disabled={loading || !/^\d{6}$/.test(otp)}
                sx={{ mt: 3, mb: 2 }}
              >
                {loading ? <CircularProgress size={24} /> : 'Verify OTP'}
              </Button>
              <Button
                fullWidth
                color="primary"
                onClick={() => {
                  setShowOTPInput(false);
                  setOtp('');
                  setError('');
                }}
              >
                Back to Registration
              </Button>
            </form>
          )}
          <Box sx={{ mt: 2, textAlign: 'center' }}>
            <Typography>
              Already have an account?{' '}
              <Button color="primary" onClick={() => navigate('/login')}>
                Login
              </Button>
            </Typography>
          </Box>
        </Paper>
      </Box>
    </Container>
  );
};

export default Register;
