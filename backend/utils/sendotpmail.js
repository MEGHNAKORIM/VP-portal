const nodemailer = require('nodemailer');

const sendotpmail = async (options) => {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT),
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      debug: true
    });

    await transporter.verify();

    const message = {
      from: `"VP Portal" <${process.env.SMTP_USER}>`,
      to: options.email,
      subject: options.subject,
      html: options.html || options.message.replace(/\n/g, '<br>')
    };

    const info = await transporter.sendMail(message);

    console.log('Email sent successfully!');
    console.log('Message ID:', info.messageId);
    console.log('Preview URL:', nodemailer.getTestMessageUrl(info));

    return info;
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
};

module.exports = sendotpmail;
