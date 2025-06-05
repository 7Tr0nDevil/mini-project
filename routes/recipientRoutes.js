const express = require("express");
const router = express.Router();
const recipientController = require("../controllers/recipientController");
const authMiddleware = require("../middleware/authMiddleware");

// ✅ Create recipient (logged-in recipient only)
router.post("/", authMiddleware, recipientController.createRecipient);

// ✅ Get all recipients (admin only)
router.get("/", authMiddleware, recipientController.getAllRecipients);

// ✅ Get logged-in recipient's own record
router.get("/me", authMiddleware, recipientController.getMyRecipientRecord);

module.exports = router;


