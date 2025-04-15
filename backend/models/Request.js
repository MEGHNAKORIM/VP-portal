const mongoose = require('mongoose');

const requestSchema = new mongoose.Schema({
  requestId: {
    type: String,
    unique: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  subject: {
    type: String,
    required: [true, 'Please specify the subject of your request'],
    enum: ['course-related', 'faculty-request', 'administrative', 'other']
  },
  description: {
    type: String,
    required: [true, 'Please provide a description'],
    trim: true
  },
  attachments: [{
    fileName: String,
    filePath: String,
    fileType: String,
    fileSize: Number,
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  adminResponse: {
    type: String,
    trim: true
  },
  adminActionDate: Date,
  adminActionBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  remarksHistory: [{
    remark: {
      type: String,
      required: true,
      trim: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for formatted dates
requestSchema.virtual('createdAtFormatted').get(function() {
  return this.createdAt.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
});

// Virtual for formatted admin action date
requestSchema.virtual('adminActionDateFormatted').get(function() {
  return this.adminActionDate ? this.adminActionDate.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }) : null;
});

// Pre-save middleware to generate request ID
requestSchema.pre('save', async function(next) {
  if (!this.requestId) {
    const count = await mongoose.model('Request').countDocuments();
    this.requestId = `REQ-${String(count + 1).padStart(3, '0')}`;
  }
  next();
});

module.exports = mongoose.model('Request', requestSchema);
