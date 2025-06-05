const mongoose = require("mongoose");

const UserDetailsSchema = new mongoose.Schema({
  user_id: { type: String, required: true, unique: true }, // 🔹 Add unique constraint
  first_name: { type: String, required: true },
  last_name: { type: String, required: true },
  address: { type: String, required: true },
  age: { type: Number, required: true },
  gender: { type: String, required: true, enum: ["Male", "Female", "Other"] },
  blood_group: { type: String, required: true }
});

module.exports = mongoose.model("UserDetails", UserDetailsSchema);


