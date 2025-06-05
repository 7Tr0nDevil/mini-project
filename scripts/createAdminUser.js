const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
require('dotenv').config();

const createAdminUser = async () => {
  try {
    // Hardcoded MongoDB connection string for testing
    const MONGO_URI = 'mongodb://localhost:27017/organhub';
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');

    const username = 'Kushal15'; // Change as needed
    const password = 'kushal123'; // Change as needed
    const email = '01fe23bca230@kletech.ac.in'; // Change as needed

    const existingAdmin = await User.findOne({ username });
    if (existingAdmin) {
      console.log('Admin user already exists');
      process.exit(0);
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const adminUser = new User({
      name: 'Administrator',
      username,
      email,
      phone: '+10000000000',
      password: hashedPassword,
      role: 'admin',
      isVerified: true,
    });

    await adminUser.save();
    console.log('Admin user created successfully');
    console.log(`Username: ${username}`);
    console.log(`Password: ${password}`);

    process.exit(0);
  } catch (error) {
    console.error('Error creating admin user:', error);
    process.exit(1);
  }
};

createAdminUser();
