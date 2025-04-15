import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  Alert,
  MenuItem,
} from '@mui/material';

const CreateRequest = () => {
  const [formData, setFormData] = useState({
    subject: '',
    description: '',
  });
  const [file, setFile] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.size > 5 * 1024 * 1024) { // 5MB limit
      setError('File size must be less than 5MB');
      return;
    }
    setFile(selectedFile);
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // Validate form data
      if (!formData.subject || !formData.description) {
        setError('Please fill in all required fields');
        setLoading(false);
        return;
      }

      // First, upload the file if one is selected
      let attachmentUrl = '';
      if (file) {
        // Validate file size
        if (file.size > 5 * 1024 * 1024) {
          setError('File size must be less than 5MB');
          setLoading(false);
          return;
        }

        const uploadFormData = new FormData();
        uploadFormData.append('file', file);

        try {
          const uploadRes = await axios.post(
            'http://localhost:5000/api/upload',
            uploadFormData,
            {
              headers: {
                'Content-Type': 'multipart/form-data',
                Authorization: `Bearer ${localStorage.getItem('token')}`,
              },
              onUploadProgress: (progressEvent) => {
                const percentCompleted = Math.round(
                  (progressEvent.loaded * 100) / progressEvent.total
                );
                console.log('Upload progress:', percentCompleted);
              },
            }
          );

          if (!uploadRes.data.success) {
            throw new Error(uploadRes.data.message || 'File upload failed');
          }

          attachmentUrl = uploadRes.data.filePath;
        } catch (uploadError) {
          console.error('File upload error:', uploadError);
          setError(
            uploadError.response?.data?.message ||
            uploadError.message ||
            'Error uploading file. Please try again.'
          );
          setLoading(false);
          return;
        }
      }

      // Then create the request
      const requestData = {
        subject: formData.subject,
        description: formData.description,
      };

      if (attachmentUrl) {
        requestData.attachments = [{
          fileName: file.name,
          filePath: attachmentUrl,
          fileType: file.type,
          fileSize: file.size
        }];
      }

      const token = localStorage.getItem('token');
      if (!token) {
        setError('You must be logged in to create a request');
        setLoading(false);
        return;
      }

      await axios.post(
        'http://localhost:5000/api/requests',
        requestData,
        {
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        }
      );

      navigate('/dashboard');
    } catch (error) {
      console.error('Error creating request:', error);
      if (error.response?.status === 401) {
        setError('Please log in again to create a request');
      } else {
        setError(
          error.response?.data?.message ||
          'Error creating request. Please try again.'
        );
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 8, mb: 4 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Typography variant="h4" align="center" gutterBottom>
            Create New Request
          </Typography>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <form onSubmit={handleSubmit}>
            <TextField
              fullWidth
              select
              label="Subject"
              name="subject"
              value={formData.subject}
              onChange={handleChange}
              margin="normal"
              required
            >
              <MenuItem value="course-related">Course Related</MenuItem>
              <MenuItem value="faculty-request">Faculty Request</MenuItem>
              <MenuItem value="administrative">Administrative</MenuItem>
              <MenuItem value="other">Other</MenuItem>
            </TextField>
            <TextField
              fullWidth
              label="Description"
              name="description"
              value={formData.description}
              onChange={handleChange}
              margin="normal"
              required
              multiline
              rows={4}
            />
            <Box sx={{ mt: 2 }}>
              <input
                accept="*/*"
                style={{ display: 'none' }}
                id="raised-button-file"
                type="file"
                onChange={handleFileChange}
              />
              <label htmlFor="raised-button-file">
                <Button variant="outlined" component="span">
                  Upload File
                </Button>
              </label>
              {file && (
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Selected file: {file.name}
                </Typography>
              )}
            </Box>
            <Button
              type="submit"
              fullWidth
              variant="contained"
              color="primary"
              sx={{ mt: 3 }}
              disabled={loading}
            >
              {loading ? 'Submitting...' : 'Submit Request'}
            </Button>
          </form>
        </Paper>
      </Box>
    </Container>
  );
};

export default CreateRequest;
