//backend--models--recipient.js
const mongoose = require("mongoose");

const recipientSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  name: { type: String, required: true },
  address: { type: String, required: true },
  gender: { type: String, required: true },
  age: { type: Number, required: true },
  phone_no: { type: String, required: true },
  bloodType: { type: String, required: true },
  organNeeded: { type: String, required: true },
  recipient_id: { type: String, unique: true }
}, { timestamps: true }); // ✅ adds createdAt, updatedAt

module.exports = mongoose.model("Recipient", recipientSchema);
