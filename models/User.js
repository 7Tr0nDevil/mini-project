const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: String,
  address: String,
  gender: String,
  age: String,
  phone: { type: String, required: true },
  email: String,
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  role: { type: String, enum: ['admin', 'donor', 'recipient'], default: 'recipient' },
  otp: String,
  otpExpiry: Date,
  resetToken: String,
  resetTokenExpiry: Date
});

module.exports = mongoose.model('User', UserSchema);
