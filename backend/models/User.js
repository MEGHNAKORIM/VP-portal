const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please enter your name']
  },
  email: {
    type: String,
    required: [true, 'Please enter your email'],
    unique: true
  },
  password: {
    type: String,
    required: [true, 'Please enter your password'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false // This ensures password isn't returned in queries by default
  },
  role: {
    type: String,
    enum: ['student', 'faculty', 'admin'],
    default: 'student'
  },

  school: {
    type: String,
    required: [true, 'Please enter your school'],
    enum: [
      'School of Technology',
      'School of Sciences',
      'School of Architecture and Planning',
      'School of Business',
      'School of Arts and Design',
      'School of Liberal Arts and Humanities',
      'School of Law'
    ]
  },
  phone: {
    type: String,
    required: [true, 'Please enter your phone number']
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationOTP: String,
  emailVerificationOTPExpire: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Encrypt password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  
  try {
    // Generate a salt
    const salt = await bcrypt.genSalt(12);
    
    // Hash the password
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare entered password with stored password
userSchema.methods.matchPassword = async function(enteredPassword) {
  try {
    return await bcrypt.compare(enteredPassword, this.password);
  } catch (error) {
    throw new Error('Error comparing passwords');
  }
};

// Generate OTP for email verification
userSchema.methods.generateEmailVerificationOTP = function() {
  // Generate 6 digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  // Hash OTP
  this.emailVerificationOTP = crypto
    .createHash('sha256')
    .update(otp)
    .digest('hex');

  // Set expiry to 10 minutes
  this.emailVerificationOTPExpire = Date.now() + 10 * 60 * 1000;

  return otp;
};

// Generate and hash password reset token
userSchema.methods.getResetPasswordToken = function() {
  // Generate token
  const resetToken = crypto.randomBytes(32).toString('hex');

  // Hash token and set to resetPasswordToken field
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // Set expire
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

  return resetToken;
};

module.exports = mongoose.model('User', userSchema);
