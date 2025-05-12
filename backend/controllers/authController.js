const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { storeTempRegistration, verifyOTP } = require('../utils/tempStorage');
const sendotpmail = require('../utils/sendotpmail');

const errorHandler = (err, res) => {
  console.error(err);
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return res.status(400).json({ success: false, message: messages.join(', ') });
  }
  res.status(500).json({ success: false, message: 'Server error' });
};

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d'
  });
};

exports.register = async (req, res) => {
  try {
    const { name, email, password, role, school, phone } = req.body;

    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long' });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    if (!email.endsWith('@woxsen.edu.in')) {
      return res.status(400).json({ success: false, message: 'Please use your Woxsen email address for registration' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
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

    const verificationEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Verify Your Email</h2>
        <p>Dear ${name},</p>
        <p>Thank you for registering. Please use the following OTP to verify your email address:</p>
        <div style="margin: 20px 0; padding: 15px; background-color: #f5f5f5; text-align: center;">
          <h1 style="color: #4CAF50; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
        </div>
        <p>This OTP will expire in 10 minutes.</p>
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
          <p>Best regards,<br>VP Portal Team</p>
        </div>
      </div>
    `;

    await sendotpmail({
      email: normalizedEmail,
      subject: 'Email Verification - VP Portal',
      html: verificationEmailHtml
    });

    res.status(200).json({
      success: true,
      message: 'Please check your email for verification OTP.',
      email
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

exports.verifyEmail = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Please provide both email and OTP' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const normalizedOtp = otp.toString().trim();

    const tempRegistrations = require('../utils/tempStorage').getTempRegistrations();
    const registration = tempRegistrations.get(normalizedEmail);

    if (!registration) {
      return res.status(400).json({ success: false, message: 'No pending registration found. Please register again.' });
    }

    if (Date.now() > registration.expiry) {
      tempRegistrations.delete(normalizedEmail);
      return res.status(400).json({ success: false, message: 'OTP has expired. Please register again.' });
    }

    if (registration.otp !== normalizedOtp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP. Please try again.' });
    }

    const { otp: _, expiry: __, ...userData } = registration;

    const user = await User.create(userData);
    tempRegistrations.delete(normalizedEmail);

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
    res.status(500).json({ success: false, message: error.message });
  }
};

exports.resendOTP = async (req, res) => {
  try {
    const { userId } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.emailVerified) {
      return res.status(400).json({ success: false, message: 'Email already verified' });
    }

    const otp = user.generateEmailVerificationOTP();
    await user.save();

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
          <p>Best regards,<br>VP Portal Team</p>
        </div>
      </div>
    `;

    await sendotpmail({
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

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Please provide an email and password' });
    }

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = generateToken(user._id);
    user.password = undefined;

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
    res.status(500).json({ success: false, message: error.message });
  }
};

exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.status(200).json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Please provide an email address' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: 'No user found with this email' });
    }

    const resetToken = user.getResetPasswordToken();
    await user.save();

    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
    const message = `You are receiving this email because you (or someone else) has requested to reset your password. Click the link below to reset your password:\n\n${resetUrl}\n\nThis link will expire in 10 minutes.`;

    await sendotpmail({
      email: user.email,
      subject: 'Password Reset Request',
      message
    });

    res.status(200).json({ success: true, message: 'Password reset link sent to email' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(req.params.resetToken)
      .digest('hex');

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
    }

    if (req.body.password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long' });
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      token,
      message: 'Password reset successful'
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
