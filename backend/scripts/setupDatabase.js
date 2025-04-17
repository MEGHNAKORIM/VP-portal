const mongoose = require('mongoose');
const User = require('../models/User');
require('dotenv').config({ path: '../config/config.env' });

const setupDatabase = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('MongoDB Connected');

    // Create admin user
    const adminData = {
      name: 'Meghana',
      email: 'meghna@gmail.com',
      password: 'Meghana@123',
      role: 'admin',
      department: 'Administration',
      school: 'Admin Department',
      phone: '1234567890'
    };

    // Delete existing admin if exists
    await User.deleteOne({ email: adminData.email });

    // Create new admin
    const admin = await User.create(adminData);
    console.log('Admin user created successfully:', admin.email);
    console.log('You can now login with:');
    console.log('Email:', adminData.email);
    console.log('Password:', adminData.password);

  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    process.exit(0);
  }
};

setupDatabase();
