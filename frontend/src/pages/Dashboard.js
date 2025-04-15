import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  Container,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Box,
  Button,
  Grid,
  Avatar,
  IconButton,
  Menu,
  MenuItem,
  CircularProgress,
  Alert,
  Tooltip
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import LogoutIcon from '@mui/icons-material/Logout';
import EditIcon from '@mui/icons-material/Edit';
import RequestForm from '../components/RequestForm';

const Dashboard = () => {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);
  const [anchorEl, setAnchorEl] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleMenuClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  const handleClose = () => {
    setShowForm(false);
    setSelectedRequest(null);
  };

  const handleEdit = (request) => {
    setSelectedRequest(request);
    setShowForm(true);
  };

  const handleSubmit = async (formData) => {
    setLoading(true);
    setError('');

    try {
      let response;
      if (selectedRequest) {
        // Update existing request
        response = await axios.put(
          `http://localhost:5000/api/requests/${selectedRequest._id}`,
          formData,
          { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }
        );
        setRequests(requests.map(req => 
          req._id === selectedRequest._id ? response.data.data : req
        ));
      } else {
        // Create new request
        response = await axios.post(
          'http://localhost:5000/api/requests',
          formData,
          { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }
        );
        setRequests([...requests, response.data.data]);
      }
      setShowForm(false);
      setSelectedRequest(null);
    } catch (error) {
      setError(error.response?.data?.message || 'Error submitting request');
    } finally {
      setLoading(false);
    }
  };

  const fetchUserProfile = useCallback(async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:5000/api/users/me', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUser(response.data);
    } catch (error) {
      console.error('Error fetching profile:', error);
      if (error.response?.status === 401) {
        navigate('/login');
      }
    }
  }, [navigate]);

  const fetchRequests = useCallback(async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:5000/api/requests/me', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setRequests(response.data.data);
    } catch (error) {
      console.error('Error fetching requests:', error);
      if (error.response?.status === 401) {
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    fetchUserProfile();
    fetchRequests();
    const interval = setInterval(fetchRequests, 5000);
    return () => clearInterval(interval);
  }, [fetchUserProfile, fetchRequests]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'approved':
        return 'success';
      case 'rejected':
        return 'error';
      default:
        return 'warning';
    }
  };

  if (loading) {
    return (
      <Container>
        <Typography>Loading...</Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg">
      <Box sx={{ mt: 4, mb: 4 }}>

        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
          <Typography variant="h4">My Requests</Typography>
        </Box>
        {showForm && (
          <RequestForm
            handleClose={handleClose}
            handleSubmit={handleSubmit}
            selectedRequest={selectedRequest}
            error={error}
          />
        )}
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Request ID</TableCell>
                <TableCell>Subject</TableCell>
                <TableCell>Description</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Created At</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {requests.map((request) => (
                <TableRow key={request._id}>
                  <TableCell>{request.requestId}</TableCell>
                  <TableCell>{request.subject}</TableCell>
                  <TableCell>{request.description}</TableCell>
                  <TableCell>
                    <Chip
                      label={request.status}
                      color={getStatusColor(request.status)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    {new Date(request.createdAt).toLocaleDateString()}
                  </TableCell>

                </TableRow>
              ))}
              {requests.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} align="center">
                    No requests found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>
    </Container>
  );
};

export default Dashboard;
