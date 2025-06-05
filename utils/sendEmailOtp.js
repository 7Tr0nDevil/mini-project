const nodemailer = require("nodemailer");
require("dotenv").config();

const sendEmailOtp = async (email, otp) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail", // You can change this to Outlook, Yahoo, etc.
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"OrganHub" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "OrganHub OTP Verification",
      text: `Your OTP is: ${otp}. It is valid for 5 minutes.`,
    };

    await transporter.sendMail(mailOptions);
    console.log("✅ OTP sent to email:", email);
  } catch (err) {
    console.error("❌ Failed to send email OTP:", err.message);
    throw new Error("OTP sending failed");
  }
};

module.exports = sendEmailOtp;
