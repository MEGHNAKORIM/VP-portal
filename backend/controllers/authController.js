const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { storeTempRegistration, verifyOTP } = require('../utils/tempStorage');
const sendEmail = require('../utils/sendEmail');

// Error Handler
const errorHandler = (err, res) => {
  console.error(err);
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return res.status(400).json({ success: false, message: messages.join(', ') });
  }
  res.status(500).json({ success: false, message: 'Server error' });
};

// Generate JWT Token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d'
  });
};

// Register user - Step 1: Send OTP
exports.register = async (req, res) => {
  console.log('Registration request received:', req.body);
  try {
    const { name, email, password, role, school, phone } = req.body;

    // Validate password strength
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }

    // Check if user exists and validate Woxsen email for registration
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    // Validate Woxsen email for registration
    if (!email.endsWith('@woxsen.edu.in')) {
      return res.status(400).json({
        success: false,
        message: 'Please use your Woxsen email address for registration'
      });
    }

    // Generate OTP (6 digits)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('Generated OTP:', otp);

    // Store registration data temporarily
    const normalizedEmail = email.toLowerCase().trim();
    
    storeTempRegistration(normalizedEmail, {
      name,
      email: normalizedEmail,
      password,
      role,
      school,
      phone,
      emailVerified: true
    }, otp);

    // Send verification email
    const verificationEmailHtml = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Verify Your Email</h2>
      <p>Dear ${name},</p>
      <p>Thank you for registering. Please use the following OTP to verify your email address:</p>
      
      <div style="margin: 20px 0; padding: 15px; background-color: #f5f5f5; text-align: center;">
        <h1 style="color: #4CAF50; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
      </div>
      
      <p><strong>Important:</strong> Enter this exact code (copy and paste to avoid errors): ${otp}</p>
      <p>This OTP will expire in 10 minutes.</p>
      
      <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
        <p>Best regards,<br>Request Portal Team</p>
      </div>
    </div>
    `;

    await sendEmail({
      email: normalizedEmail,
      subject: 'Email Verification - Request Portal',
      html: verificationEmailHtml
    });

    return res.status(200).json({
      success: true,
      message: 'Please check your email for verification OTP.',
      email: email
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

// Verify Email OTP and Complete Registration
exports.verifyEmail = async (req, res) => {
  try {
    console.log('\n=== Starting OTP Verification ===');
    console.log('Request body:', req.body);

    const { email, otp } = req.body;
    if (!email || !otp) {
      console.log('Missing email or OTP in request');
      return res.status(400).json({
        success: false,
        message: 'Please provide both email and OTP'
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const normalizedOtp = otp.toString().trim();

    console.log('Attempting verification:', {
      email: normalizedEmail,
      otp: normalizedOtp
    });

    // Get current registrations
    const tempRegistrations = require('../utils/tempStorage').getTempRegistrations();
    const registration = tempRegistrations.get(normalizedEmail);

    if (!registration) {
      console.log('No registration found for:', normalizedEmail);
      return res.status(400).json({
        success: false,
        message: 'No pending registration found. Please register again.'
      });
    }

    if (Date.now() > registration.expiry) {
      console.log('OTP expired for:', normalizedEmail);
      tempRegistrations.delete(normalizedEmail);
      return res.status(400).json({
        success: false,
        message: 'OTP has expired. Please register again.'
      });
    }

    console.log('Comparing OTPs:', {
      stored: registration.otp,
      received: normalizedOtp,
      match: registration.otp === normalizedOtp
    });

    if (registration.otp !== normalizedOtp) {
      return res.status(400).json({
        success: false,
        message: 'Invalid OTP. Please try again.'
      });
    }

    // Create new user
    const { otp: _, expiry: __, ...userData } = registration;
    console.log('Creating user with data:', userData);

    const user = await User.create(userData);
    console.log('User created successfully:', user._id);

    // Remove registration data
    tempRegistrations.delete(normalizedEmail);

    // Generate token
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: 'Registration successful!',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        school: user.school,
        phone: user.phone
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

// Resend OTP
exports.resendOTP = async (req, res) => {
  try {
    const { userId } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.emailVerified) {
      return res.status(400).json({
        success: false,
        message: 'Email already verified'
      });
    }

    // Generate new OTP
    const otp = user.generateEmailVerificationOTP();
    await user.save();

    // Send verification email
    const verificationEmailHtml = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Verify Your Email</h2>
      <p>Dear ${user.name},</p>
      <p>Your new OTP for email verification is:</p>
      
      <div style="margin: 20px 0; padding: 15px; background-color: #f5f5f5; text-align: center;">
        <h1 style="color: #4CAF50; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
      </div>
      
      <p>This OTP will expire in 10 minutes.</p>
      
      <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
        <p>Best regards,<br>Request Portal Team</p>
      </div>
    </div>
    `;

    await sendEmail({
      email: user.email,
      subject: 'New OTP - Email Verification',
      html: verificationEmailHtml
    });

    res.status(200).json({
      success: true,
      message: 'New OTP sent to your email'
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Login user
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate email & password
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email and password'
      });
    }

    // Check for user and include password field
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if password matches
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate token
    const token = generateToken(user._id);

    // Remove password from response
    user.password = undefined;

    // Send response
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        school: user.school,
        phone: user.phone
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

// Get current user
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.status(200).json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Forgot Password
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Check if email exists
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email address'
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'No user found with this email'
      });
    }

    // Get reset token
    const resetToken = user.getResetPasswordToken();
    await user.save();

    // Create reset url
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
    const message = `You are receiving this email because you (or someone else) has requested to reset your password. Click the link below to reset your password:\n\n${resetUrl}\n\nThis link will expire in 10 minutes.`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Password Reset Request',
        message
      });

      res.status(200).json({
        success: true,
        message: 'Password reset link sent to email'
      });
    } catch (error) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();

      return res.status(500).json({
        success: false,
        message: 'Email could not be sent'
      });
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

// Reset Password
exports.resetPassword = async (req, res) => {
  try {
    // Get hashed token
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(req.params.resetToken)
      .digest('hex');

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
    }

    // Validate password strength
    if (req.body.password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }

    // Set new password
    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    // Generate new token
    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      token,
      message: 'Password reset successful'
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};
