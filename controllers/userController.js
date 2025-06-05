const User = require("../models/User");
const sendOtp = require("../utils/sendEmailOtp");
const bcrypt = require("bcryptjs");

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

// ✅ Forgot Password – send OTP
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otp = generateOtp();
    user.otp = otp;
    user.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();

    await sendOtp(email, otp);
    console.log("✅ OTP sent to:", email);

    res.status(200).json({ message: "OTP sent to your email", username: user.username });
  } catch (err) {
    console.error("❌ Error in forgotPassword:", err.message);
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

// ✅ Verify OTP
exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({
      email: new RegExp(`^${email}$`, 'i'),
      otp,
      otpExpiry: { $gt: new Date() },
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired OTP" });

    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    console.log("✅ OTP verified for:", email);
    res.status(200).json({ message: "OTP verified successfully" });
  } catch (err) {
    console.error("❌ Error in verifyOtp:", err.message);
    res.status(500).json({ message: "Verification failed", error: err.message });
  }
};

// ✅ Reset Password – make sure hashed and saved
exports.resetPassword = async (req, res) => {
  const { email, username, newPassword } = req.body;

  try {
    console.log("📥 Password reset request:", { email, username });

    const user = await User.findOne({
      email: new RegExp(`^${email}$`, 'i'),
      username: new RegExp(`^${username}$`, 'i'),
    });

    if (!user) {
      console.log("❌ No user found for password reset");
      return res.status(404).json({ message: "User not found" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Important: reset OTP fields
    user.otp = null;
    user.otpExpiry = null;

    await user.save();

    console.log("✅ Password reset successful for:", username);
    res.status(200).json({ message: "Password reset successful. Please log in with your new password." });
  } catch (err) {
    console.error("❌ Password reset error:", err.message);
    res.status(500).json({ message: "Password reset failed", error: err.message });
  }
};

