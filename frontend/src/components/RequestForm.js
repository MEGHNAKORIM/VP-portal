import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemSecondary,
  IconButton
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';

const schools = [
  'School of Technology',
  'School of Sciences',
  'School of Architecture and Planning',
  'School of Business',
  'School of Arts and Design',
  'School of Liberal Arts and Humanities',
  'School of Law'
];

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ACCEPTED_FILE_TYPES = '.pdf,.doc,.docx,.xls,.xlsx,.jpg,.jpeg,.png';

const RequestForm = ({ open, onClose, onSubmit, initialData = null }) => {
  const [formData, setFormData] = useState({
    subject: '',
    description: '',
    attachments: []
  });
  const [errors, setErrors] = useState({});
  const [uploadedFiles, setUploadedFiles] = useState([]);

  useEffect(() => {
    if (initialData) {
      setFormData({
        subject: initialData.subject || '',
        description: initialData.description || '',
        attachments: initialData.attachments || []
      });
      setUploadedFiles(initialData.attachments || []);
    }
  }, [initialData]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    // Clear error when user types
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const handleFileChange = (e) => {
    const files = Array.from(e.target.files);
    const newErrors = {};
    
    files.forEach(file => {
      if (file.size > MAX_FILE_SIZE) {
        newErrors.files = `${file.name} exceeds 5MB limit`;
      }
    });

    if (Object.keys(newErrors).length > 0) {
      setErrors(prev => ({ ...prev, ...newErrors }));
      return;
    }

    const filePromises = files.map(file => {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          resolve({
            fileName: file.name,
            fileSize: file.size,
            fileType: file.type,
            fileData: reader.result.split(',')[1] // Get base64 data
          });
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    });

    Promise.all(filePromises)
      .then(fileData => {
        setUploadedFiles(prev => [...prev, ...fileData]);
        setFormData(prev => ({
          ...prev,
          attachments: [...(prev.attachments || []), ...fileData]
        }));
      })
      .catch(error => {
        console.error('Error processing files:', error);
        setErrors(prev => ({ ...prev, files: 'Error processing files' }));
      });
  };

  const handleRemoveFile = (index) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleSubmit = () => {
    const newErrors = {};
    
    if (!formData.subject.trim()) {
      newErrors.subject = 'Subject is required';
    }
    if (!formData.description.trim()) {
      newErrors.description = 'Description is required';
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    onSubmit({ ...formData, files: uploadedFiles });
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{initialData ? 'Edit Request' : 'New Request'}</DialogTitle>
      <DialogContent>
        <TextField
          margin="normal"
          fullWidth
          label="Subject"
          name="subject"
          value={formData.subject}
          onChange={handleChange}
          error={!!errors.subject}
          helperText={errors.subject}
        />
        <TextField
          margin="normal"
          fullWidth
          label="Description"
          name="description"
          multiline
          rows={4}
          value={formData.description}
          onChange={handleChange}
          error={!!errors.description}
          helperText={errors.description}
        />


        <div style={{ marginTop: 20 }}>
          <Typography variant="subtitle1">Attachments</Typography>
          <Typography variant="caption" color="textSecondary">
            Maximum file size: 5MB
            <br />
            Accepted file types: PDF, DOC, DOCX, XLS, XLSX, JPG, JPEG, PNG
          </Typography>
          <input
            accept={ACCEPTED_FILE_TYPES}
            style={{ display: 'none' }}
            id="raised-button-file"
            multiple
            type="file"
            onChange={handleFileChange}
          />
          <label htmlFor="raised-button-file">
            <Button
              variant="outlined"
              component="span"
              style={{ marginTop: 10 }}
            >
              Upload Files
            </Button>
          </label>
          {errors.files && (
            <Typography color="error" variant="caption" display="block">
              {errors.files}
            </Typography>
          )}
        </div>

        {uploadedFiles.length > 0 && (
          <List>
            {uploadedFiles.map((file, index) => (
              <ListItem
                key={index}
                secondaryAction={
                  <IconButton edge="end" onClick={() => handleRemoveFile(index)}>
                    <DeleteIcon />
                  </IconButton>
                }
              >
                <ListItemText
                  primary={file.fileName}
                  secondary={formatFileSize(file.fileSize)}
                />
              </ListItem>
            ))}
          </List>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" color="primary">
          {initialData ? 'Update' : 'Submit'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default RequestForm;
