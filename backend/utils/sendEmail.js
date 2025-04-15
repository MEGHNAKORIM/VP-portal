const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  try {
    // Create transporter
    console.log('Creating email transporter with:', {
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      user: process.env.SMTP_USER
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT),
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS // Using app password
      },
      debug: true
    });

    // Verify transporter
    await transporter.verify();
    console.log('SMTP connection verified successfully');

    const message = {
      from: `"Request Portal" <${process.env.SMTP_USER}>`,
      to: options.email,
      cc: options.cc || 'vamsidharareddy.alam_2026@woxsen.edu.in',
      subject: options.subject,
      html: options.html || options.message.replace(/\n/g, '<br>')
    };

    console.log('Sending email to:', options.email);
    console.log('Email subject:', options.subject);

    const info = await transporter.sendMail(message);
    
    console.log('Email sent successfully!');
    console.log('Message ID:', info.messageId);
    console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
    
    return info;
  } catch (error) {
    console.error('Error sending email:', error);
    console.error('Error details:', {
      code: error.code,
      command: error.command,
      response: error.response
    });
    throw error;
  }
};

module.exports = sendEmail;
