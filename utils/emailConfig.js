const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
dotenv.config();

// Configure nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false // Only for development
  }
});

// Verify transporter configuration
async function verifyEmailConfig() {
  try {
    await transporter.verify();
    console.log('Email service is ready to send emails');
    return true;
  } catch (error) {
    console.error('Email service configuration error:', error);
    return false;
  }
}

module.exports = {
  transporter,
  verifyEmailConfig
};