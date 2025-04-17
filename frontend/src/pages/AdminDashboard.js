import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
   CircularProgress

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

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

const AdminDashboard = () => {
  const [user, setUser] = useState(null);
  const [anchorEl, setAnchorEl] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [remarks, setRemarks] = useState('');
  const [response, setResponse] = useState('');
  const [actionMessage, setActionMessage] = useState('');
  const [isActionLoading, setIsActionLoading] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [requests, setRequests] = useState([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [nameFilter, setNameFilter] = useState('');
  const [requestIdFilter, setRequestIdFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [chartData, setChartData] = useState([]);
  const [requestTypes, setRequestTypes] = useState([]);
  const [timeFilter, setTimeFilter] = useState('all');
  const [stats, setStats] = useState({
    total: 0,
    approved: 0,
    rejected: 0,
    pending: 0
  });
  const [currentPage, setCurrentPage] = useState(1);
  const requestsPerPage = 10;

  const navigate = useNavigate();

  useEffect(() => {
    fetchRequests();
    const interval = setInterval(fetchRequests, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Process data for charts when requests change
    const processChartData = () => {
      const now = new Date();
      let filteredRequests = [...requests];

      // Apply time filter
      if (timeFilter !== 'all') {
        const filterDate = new Date();
        switch (timeFilter) {
          case 'day':
            filterDate.setDate(filterDate.getDate() - 1);
            break;
          case 'week':
            filterDate.setDate(filterDate.getDate() - 7);
            break;
          case 'month':
            filterDate.setMonth(filterDate.getMonth() - 1);
            break;
          default:
            break;
        }
        filteredRequests = requests.filter(request => 
          new Date(request.createdAt) > filterDate
        );
      }

      // Calculate statistics
      const newStats = {
        total: filteredRequests.length,
        approved: filteredRequests.filter(r => r.status === 'approved').length,
        rejected: filteredRequests.filter(r => r.status === 'rejected').length,
        pending: filteredRequests.filter(r => r.status === 'pending').length
      };
      setStats(newStats);

      // Group requests by date
      const requestsByDate = {};
      filteredRequests.forEach(request => {
        const date = new Date(request.createdAt).toLocaleDateString();
        requestsByDate[date] = requestsByDate[date] || {
          date,
          total: 0,
          approved: 0,
          rejected: 0,
          pending: 0
        };
        requestsByDate[date].total++;
        requestsByDate[date][request.status]++;
      });

      // Convert to chart format
      const chartData = Object.values(requestsByDate)
        .sort((a, b) => new Date(a.date) - new Date(b.date));

      setChartData(chartData);
      setRequestTypes(Array.from(new Set(filteredRequests.map(r => r.subject))));
    };

    processChartData();
  }, [requests, timeFilter]);

  const fetchRequests = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        navigate('/login');
        return;
      }

      // Set default headers for all axios requests
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

      const response = await axios.get(`${process.env.REACT_APP_BACKEND_URL}/api/requests/all`);
      
      if (response.data.success) {
        setRequests(response.data.data);

        // Update request counts
        const counts = response.data.data.reduce((acc, request) => {
          acc[request.status] = (acc[request.status] || 0) + 1;
          return acc;
        }, {});

        setStats({
          total: response.data.data.length,
          approved: counts.approved || 0,
          rejected: counts.rejected || 0,
          pending: counts.pending || 0
        });
      } else {
        throw new Error('Failed to fetch requests');
      }
    } catch (error) {
      console.error('Error fetching requests:', error);
      if (error.response?.status === 401 || error.response?.status === 403) {
        // If unauthorized, redirect to login
        navigate('/login');
        return;
      }
      // Handle other errors
      setActionMessage('Error: Failed to fetch requests. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleRequestAction = async (request, status) => {
    if (!remarks.trim()) {
      setActionMessage('Error: Please provide remarks before updating the status.');
      return;
    }
    setIsActionLoading(true);
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('Authentication token not found. Please login again.');
      }

      // Set default headers for all axios requests
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      axios.defaults.headers.common['Content-Type'] = 'application/json';

      console.log('Sending request update:', {
        requestId: request._id,
        status,
        remarks: remarks.trim()
      });

      const updatedRequest = await axios.put(
        `${process.env.REACT_APP_BACKEND_URL}/api/requests/${request._id}`,
        { 
          status,
          remark: remarks.trim()
        }
      );
      
      console.log('Response from server:', updatedRequest.data);

      if (updatedRequest.data.success) {
        // Update the selected request with new data
        setSelectedRequest(updatedRequest.data.data);
        
        // Update the request in the requests list
        setRequests(prevRequests => 
          prevRequests.map(req => 
            req._id === request._id ? updatedRequest.data.data : req
          )
        );

        // Clear remarks input
        setRemarks('');

        // Show success message
        setActionMessage(`Request ${status} successfully. Email notification has been sent.`);
        
        // Close the dialog
        setDetailsDialogOpen(false);
        
        // Refresh the requests list
        fetchRequests();
        
        // Clear message after 3 seconds
        setTimeout(() => setActionMessage(''), 3000);
      } else {
        throw new Error(updatedRequest.data.message || 'Failed to update request');
      }
    } catch (error) {
      console.error('Error updating request:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data
      });

      if (error.response?.status === 401 || error.response?.status === 403) {
        // If unauthorized, redirect to login
        navigate('/login');
        return;
      }
      setActionMessage(`Error: ${error.response?.data?.message || error.message || 'Failed to update request'}`);
    } finally {
      setIsActionLoading(false);
    }
  };

  // Function to render remarks history
  const renderRemarksHistory = (request) => {
    if (!request.remarksHistory || request.remarksHistory.length === 0) {
      return <p>No previous remarks</p>;
    }

    return (
      <div className="remarks-history">
        <h5>Remarks History</h5>
        <div className="remarks-list" style={{ maxHeight: '200px', overflowY: 'auto' }}>
          {request.remarksHistory.map((remark, index) => (
            <div key={index} className="remark-item" style={{ 
              padding: '10px', 
              margin: '5px 0', 
              backgroundColor: '#f8f9fa',
              borderRadius: '4px',
              borderLeft: '3px solid #28a745'
            }}>
              <div style={{ fontSize: '0.9rem', color: '#666' }}>
                <strong>{remark.createdBy?.name || 'Admin'}</strong> • 
                {new Date(remark.createdAt).toLocaleString()}
              </div>
              <div style={{ marginTop: '5px' }}>{remark.remark}</div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const handleSubmitResponse = async (request, status) => {
    try {
      await axios.put(`${process.env.REACT_APP_BACKEND_URL}/api/requests/${request._id}`, {
        status,
        adminResponse: response,
      });
      setDialogOpen(false);
      setResponse('');
      fetchRequests();
    } catch (error) {
      console.error('Error updating request:', error);
    }
  };

  const handleStatusUpdate = async (requestId, newStatus) => {
    try {
      const token = localStorage.getItem('token');
      await axios.put(
        `${process.env.REACT_APP_BACKEND_URL}/api/requests/${requestId}/status`,
        {
          status: newStatus,
          remarks: remarks
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      // Update local state
      setRequests(requests.map(request =>
        request._id === requestId
          ? { ...request, status: newStatus, remarks: remarks }
          : request
      ));

      // Reset remarks
      setRemarks('');
      setSelectedRequest(null);
    } catch (error) {
      console.error('Error updating status:', error);
    }
  };

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

  const handleCloseDialog = () => {
    setDialogOpen(false);
    setResponse('');
    setSelectedRequest(null);
  };

  if (loading) {
    return (
      <Container>
        <Typography>Loading...</Typography>
      </Container>
    );
  }

  // Filter requests based on name, request ID, and type
  const filteredRequests = requests.filter((request) => {
    const nameMatch = request.user?.name?.toLowerCase().includes(nameFilter.toLowerCase());
    const requestIdMatch = request.requestId?.toLowerCase().includes(requestIdFilter.toLowerCase());
    const typeMatch = typeFilter === 'all' || request.subject === typeFilter;
    return nameMatch && requestIdMatch && typeMatch;
  });

  // Pagination logic
  const indexOfLastRequest = currentPage * requestsPerPage;
  const indexOfFirstRequest = indexOfLastRequest - requestsPerPage;
  const currentRequests = filteredRequests.slice(indexOfFirstRequest, indexOfLastRequest);
  const totalPages = Math.ceil(filteredRequests.length / requestsPerPage);

  return (
    <Container maxWidth="lg">
      <Box sx={{ mt: 4, mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Admin Dashboard - Manage Requests
        </Typography>

        {/* Statistics Cards */}
        <Grid container spacing={2} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'primary.light', color: 'white' }}>
              <Typography variant="h6">Total Requests</Typography>
              <Typography variant="h4">{stats.total}</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'success.light', color: 'white' }}>
              <Typography variant="h6">Approved</Typography>
              <Typography variant="h4">{stats.approved}</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'error.light', color: 'white' }}>
              <Typography variant="h6">Rejected</Typography>
              <Typography variant="h4">{stats.rejected}</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'warning.light', color: 'white' }}>
              <Typography variant="h6">Pending</Typography>
              <Typography variant="h4">{stats.pending}</Typography>
            </Paper>
          </Grid>
        </Grid>

        {/* Filters */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              label="Filter by Request ID"
              value={requestIdFilter}
              onChange={(e) => {
                setCurrentPage(1);
                setRequestIdFilter(e.target.value);
              }}
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              label="Filter by Name"
              value={nameFilter}
              onChange={(e) => {
                setCurrentPage(1);
                setNameFilter(e.target.value);
              }}
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <FormControl fullWidth>
              <InputLabel>Filter by Request Type</InputLabel>
              <Select
                value={typeFilter}
                label="Filter by Request Type"
                onChange={(e) => {
                  setCurrentPage(1);
                  setTypeFilter(e.target.value);
                }}
              >
                <MenuItem value="all">All Types</MenuItem>
                {Array.from(new Set(requests.map(r => r.subject))).map((type) => (
                  <MenuItem key={type} value={type}>
                    {type}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
        </Grid>
        {/* Time Filter */}
        <Box sx={{ mb: 3 }}>
          <FormControl sx={{ minWidth: 200 }}>
            <InputLabel>Time Filter</InputLabel>
            <Select
              value={timeFilter}
              onChange={(e) => setTimeFilter(e.target.value)}
              label="Time Filter"
            >
              <MenuItem value="all">All Time</MenuItem>
              <MenuItem value="day">Last 24 Hours</MenuItem>
              <MenuItem value="week">Last 7 Days</MenuItem>
              <MenuItem value="month">Last 30 Days</MenuItem>
            </Select>
          </FormControl>
        </Box>

        {/* Charts */}
        <Grid container spacing={3} sx={{ mt: 2 }}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Request Statistics Over Time
              </Typography>
              <Box sx={{ height: 300 }}>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="approved" fill="#4caf50" name="Approved" />
                    <Bar dataKey="rejected" fill="#f44336" name="Rejected" />
                    <Bar dataKey="pending" fill="#ff9800" name="Pending" />
                  </BarChart>
                </ResponsiveContainer>
              </Box>
            </Paper>
          </Grid>

        </Grid>

        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Request ID</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Subject</TableCell>
                <TableCell>Description</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Created At</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {currentRequests.map((request) => (
                <TableRow key={request._id}>
                  <TableCell>{request.requestId}</TableCell>
                  <TableCell>{request.user?.name || 'N/A'}</TableCell>
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
                  <TableCell>
                    <Button
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedRequest(request);
                        setRemarks('');
                        setResponse('');
                        setDetailsDialogOpen(true);
                      }}
                    >
                      View Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

      {/* Pagination Controls */}
      <Box display="flex" justifyContent="center" alignItems="center" mt={2}>
        <Button
          variant="outlined"
          disabled={currentPage === 1}
          onClick={() => setCurrentPage((prev) => prev - 1)}
          sx={{ mr: 2 }}
        >
          Previous
        </Button>
        <Typography variant="body2" sx={{ mx: 2 }}>
          Page {currentPage} of {totalPages || 1}
        </Typography>
        <Button
          variant="outlined"
          disabled={currentPage === totalPages || totalPages === 0}
          onClick={() => setCurrentPage((prev) => prev + 1)}
          sx={{ ml: 2 }}
        >
          Next
        </Button>
      </Box>

      {/* Response Dialog */}
      <Dialog open={dialogOpen} onClose={handleCloseDialog} maxWidth="sm" fullWidth>
        <DialogTitle>Response to Request</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Admin Response (This will be sent via email)"
            fullWidth
            multiline
            rows={4}
            value={response}
            onChange={(e) => setResponse(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button
            onClick={() =>
              handleSubmitResponse(selectedRequest, selectedRequest.status)
            }
            color="primary"
            variant="contained"
          >
            Send Response
          </Button>
        </DialogActions>
      </Dialog>

      {/* Details Dialog */}
      <Dialog open={detailsDialogOpen} onClose={() => setDetailsDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Request Details</DialogTitle>
        <DialogContent>
          {selectedRequest && (
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">User Information</Typography>
                <Typography variant="body1">{selectedRequest.user?.name}</Typography>
                <Typography variant="body2" color="textSecondary">{selectedRequest.user?.email}</Typography>
                <Chip
                  label={selectedRequest.user?.role || 'N/A'}
                  color={selectedRequest.user?.role === 'faculty' ? 'primary' : 'secondary'}
                  size="small"
                  sx={{ mt: 1 }}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Request Information</Typography>
                <Typography variant="body1">Type: {selectedRequest.subject}</Typography>
                <Typography variant="body2">Status: 
                  <Chip
                    label={selectedRequest.status}
                    color={getStatusColor(selectedRequest.status)}
                    size="small"
                    sx={{ ml: 1 }}
                  />
                </Typography>
                <Typography variant="body2">
                  Created: {new Date(selectedRequest.createdAt).toLocaleString()}
                </Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="textSecondary">Description</Typography>
                <Paper variant="outlined" sx={{ p: 2, mt: 1 }}>
                  <Typography variant="body1">{selectedRequest.description}</Typography>
                </Paper>
              </Grid>
              {selectedRequest.attachments && selectedRequest.attachments.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">Attachments</Typography>
                  {selectedRequest.attachments.map((attachment, index) => (
                    <Box key={index} sx={{ mt: 2, mb: 2 }}>
                      <Typography variant="body2" gutterBottom>
                        File: {attachment.fileName} ({(attachment.fileSize / 1024).toFixed(2)} KB)
                      </Typography>
                      {attachment.filePath.toLowerCase().endsWith('.pdf') ? (
                        <iframe
                          src={`http://localhost:5000${attachment.filePath}`}
                          width="100%"
                          height="500px"
                          title="PDF Preview"
                        />
                      ) : attachment.fileType.startsWith('image/') ? (
                        <img
                          src={`http://localhost:5000${attachment.filePath}`}
                          alt={attachment.fileName}
                          style={{ maxWidth: '100%', maxHeight: '500px' }}
                        />
                      ) : (
                        <Button
                          href={`http://localhost:5000${attachment.filePath}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          variant="outlined"
                          startIcon={<span role="img" aria-label="file">📎</span>}
                        >
                          Download {attachment.fileName}
                        </Button>
                      )}
                    </Box>
                  ))}
                </Grid>
              )}
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Remarks"
                  value={remarks}
                  onChange={(e) => setRemarks(e.target.value)}
                  multiline
                  rows={3}
                  margin="normal"
                  required
                  error={!remarks.trim() && actionMessage.includes('remarks')}
                  helperText={!remarks.trim() && actionMessage.includes('remarks') ? 'Please provide remarks' : ''}
                />
                <Box sx={{ mt: 2 }}>
                  <Button
                    color="success"
                    variant="contained"
                    onClick={() => handleRequestAction(selectedRequest, 'approved')}
                    disabled={isActionLoading}
                  >
                    {isActionLoading ? (
                      <CircularProgress size={24} color="inherit" />
                    ) : (
                      'Approve'
                    )}
                  </Button>
                  <Button
                    color="error"
                    variant="contained"
                    onClick={() => handleRequestAction(selectedRequest, 'rejected')}
                    disabled={isActionLoading}
                  >
                    {isActionLoading ? (
                      <CircularProgress size={24} color="inherit" />
                    ) : (
                      'Reject'
                    )}
                  </Button>
                </Box>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
    </Container>
  );
};

export default AdminDashboard;
