const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");

router.post("/forgot-password", userController.forgotPassword);
router.post("/verify-reset-otp", userController.verifyOtp);
router.post("/reset-password", userController.resetPassword);

module.exports = router;
