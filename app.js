const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("./models/User");
const sendOtp = require("./utils/sendEmailOtp");

const donorRoutes = require("./routes/donorRoutes");
const recipientRoutes = require("./routes/recipientRoutes");
const userRoutes = require("./routes/userroutes");

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// ✅ Root route
app.get("/", (_, res) => res.send("🚀 Server is running..."));

// ✅ Routes
app.use("/api/donor", donorRoutes);
app.use("/api/recipients", recipientRoutes);
app.use("/api/users", userRoutes);

// ✅ OTP Helper
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

// ✅ Register
app.post("/api/auth/register", async (req, res) => {
    try {
        const { name, address, gender, age, phone, email, username, password, role } = req.body;

        if (!username || !password || !email) {
            return res.status(400).json({ message: "Username, password, and email are required" });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "Username already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const otp = generateOtp();
        const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

        const newUser = new User({
            name,
            address,
            gender,
            age,
            phone,
            email,
            username,
            password: hashedPassword,
            otp,
            otpExpiry,
            isVerified: false,
            role: role || "recipient"
        });

        await newUser.save();
        await sendOtp(email, otp);

        res.status(201).json({ message: "OTP sent to email" });
    } catch (err) {
        console.error("❌ Registration Error:", err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// ✅ Verify OTP
app.post("/api/auth/verify-otp", async (req, res) => {
    try {
        const { username, otp } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: "User not found" });
        if (user.isVerified) return res.status(400).json({ message: "Already verified" });

        if (user.otp !== otp || user.otpExpiry < new Date()) {
            return res.status(400).json({ message: "Invalid or expired OTP" });
        }

        user.isVerified = true;
        user.otp = null;
        user.otpExpiry = null;
        await user.save();

        res.status(200).json({ message: "OTP verified successfully" });
    } catch (err) {
        console.error("❌ OTP Verification Error:", err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// ✅ Resend OTP
app.post("/api/auth/resend-otp", async (req, res) => {
    try {
        const { username, email } = req.body;
        const user = await User.findOne({ username, email });
        if (!user) return res.status(404).json({ message: "User not found" });
        if (user.isVerified) return res.status(400).json({ message: "Already verified" });

        const newOtp = generateOtp();
        const newOtpExpiry = new Date(Date.now() + 5 * 60 * 1000);

        user.otp = newOtp;
        user.otpExpiry = newOtpExpiry;

        await user.save();
        await sendOtp(email, newOtp);

        res.status(200).json({ message: "OTP resent successfully" });
    } catch (err) {
        console.error("❌ Resend OTP Error:", err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// ✅ Login (Admin/User separation)
app.post("/api/auth/login", async (req, res) => {
    try {
        const { username, password, loginAs } = req.body;

        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Invalid password" });

        // Role check
        if (loginAs === "admin" && user.role !== "admin") {
            return res.status(403).json({ message: "Access denied: not an admin" });
        }
        if (loginAs === "user" && (user.role !== "donor" && user.role !== "recipient")) {
            return res.status(403).json({ message: "Access denied: not a regular user" });
        }

        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({
            message: "Login successful",
            token,
            role: user.role,
            username: user.username
        });

    } catch (err) {
        console.error("❌ Login Error:", err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// ✅ 404 for unknown routes
app.use((req, res) => {
    res.status(404).json({ message: "Route not found" });
});

// ✅ Start server + connect to DB
const PORT = process.env.PORT || 5001;

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("✅ MongoDB Connected");
        app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
    })
    .catch((err) => {
        console.error("❌ MongoDB Connection Error:", err.message);
    });

