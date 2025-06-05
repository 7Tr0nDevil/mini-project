const express = require("express");
const router = express.Router();
const donorController = require("../controllers/donorController");
const authMiddleware = require("../middleware/authMiddleware");

// ✅ Create donor (logged-in donor only)
router.post("/", authMiddleware, donorController.createDonor);

// ✅ Get all donors (admin only)
router.get("/", authMiddleware, donorController.getAllDonors);

// ✅ Get logged-in donor's own record
router.get("/me", authMiddleware, donorController.getMyDonorRecord);

module.exports = router;
