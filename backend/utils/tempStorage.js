// Temporary storage for registration data and OTPs
const tempRegistrations = new Map();

// Store registration data temporarily
const storeTempRegistration = (email, data, otp) => {
  const normalizedEmail = email.toLowerCase().trim();
  const normalizedOtp = otp.toString().trim();

  console.log('Storing registration:', {
    email: normalizedEmail,
    otp: normalizedOtp
  });

  tempRegistrations.set(normalizedEmail, {
    ...data,
    otp: normalizedOtp,
    expiry: Date.now() + 10 * 60 * 1000 // 10 minutes expiry
  });

  console.log('Current registrations:', 
    Array.from(tempRegistrations.entries())
      .map(([email, data]) => ({ 
        email, 
        otp: data.otp,
        expiry: new Date(data.expiry).toISOString()
      })));
};

// Verify OTP and get registration data
const verifyOTP = (email, otp) => {
  const normalizedEmail = email.toLowerCase().trim();
  const normalizedOtp = otp.toString().trim();

  console.log('Verifying OTP:', {
    email: normalizedEmail,
    inputOtp: normalizedOtp
  });

  const registration = tempRegistrations.get(normalizedEmail);
  if (!registration) {
    console.log('No registration found for:', normalizedEmail);
    return { verified: false, message: 'Registration not found or expired' };
  }

  if (Date.now() > registration.expiry) {
    console.log('OTP expired for:', normalizedEmail);
    tempRegistrations.delete(normalizedEmail);
    return { verified: false, message: 'OTP expired' };
  }

  console.log('Comparing OTPs:', {
    stored: registration.otp,
    received: normalizedOtp,
    isMatch: registration.otp === normalizedOtp
  });

  if (registration.otp !== normalizedOtp) {
    return { verified: false, message: 'Invalid OTP' };
  }

  // Success! Remove OTP and expiry from data to be saved
  console.log('DEBUG - OTP verified successfully!');
  const { otp: _, expiry: __, ...userData } = registration;
  tempRegistrations.delete(normalizedEmail);

  return { verified: true, userData };
};

// Clean up expired registrations every 15 minutes
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of tempRegistrations.entries()) {
    if (now > data.expiry) {
      console.log('DEBUG - Cleaning up expired registration:', {
        email,
        expiredAt: new Date(data.expiry).toISOString()
      });
      tempRegistrations.delete(email);
    }
  }
}, 15 * 60 * 1000);

const getTempRegistrations = () => tempRegistrations;

module.exports = { storeTempRegistration, verifyOTP, getTempRegistrations };
