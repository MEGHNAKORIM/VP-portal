const mongoose = require('mongoose');
const User = require('../models/User');
require('dotenv').config({ path: '../config/config.env' });

const createAdmin = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('MongoDB Connected');

    // Create admin user
    const adminData = {
      name: 'Meghna',
      email: 'meghnakorimi@gmail.com',
      password: 'Meghana@123',
      role: 'admin',
      department: 'Administration',
      school: 'Admin Department',
      phone: '1234567890'
    };

    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminData.email });
    if (existingAdmin) {
      console.log('Admin user already exists');
      process.exit(0);
    }

    // Create new admin
    const admin = await User.create(adminData);
    console.log('Admin user created successfully:', admin.email);

  } catch (error) {
    console.error('Error:', error.message);
  }
  process.exit(0);
};

createAdmin();
