const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
require('dotenv').config({ path: './config/config.env' });
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');

const uploadDir = path.join(__dirname, 'uploads');

fs.mkdirSync(uploadDir, { recursive: true });

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('MongoDB Connection Error:', err));

const app = express();

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());


const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Ensure uploads directory exists
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // Sanitize filename
    const fileName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
    cb(null, `${Date.now()}-${fileName}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    // Accept all file types for now
    cb(null, true);
  }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));



// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/requests', require('./routes/requestRoutes'));

// File upload endpoint
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    // Return a web-accessible URL for the uploaded file
    res.json({
      success: true,
      filePath: `/uploads/${req.file.filename}`,
      fileName: req.file.filename
    });
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Error uploading file'
    });
  }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
