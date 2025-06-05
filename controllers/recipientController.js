const Recipient = require("../models/Recipient");
const sendSMS = require("../utils/sendSMS");

// ✅ Create recipient (link to logged-in user)
exports.createRecipient = async (req, res) => {
  try {
    const recipientData = {
      userId: req.user.id,
      name: req.body.name,
      address: req.body.address,
      gender: req.body.gender,
      age: req.body.age,
      phone_no: req.body.phone_no,
      bloodType: req.body.bloodType,
      organNeeded: req.body.organNeeded,
      recipient_id: req.body.recipient_id
    };

    const savedRecipient = await Recipient.create(recipientData);
    console.log("✅ Recipient saved:", savedRecipient);

    let phone = req.body.phone_no.replace(/\D/g, "");
    if (!phone.startsWith("91")) {
      phone = "91" + phone;
    }
    phone = "+" + phone;
    console.log("📱 Final phone number to send SMS:", phone);

    const smsMessage = `🩺 Hello ${req.body.name}, you have successfully registered as a recipient for ${req.body.organNeeded} on OrganHub.`;

    try {
      await sendSMS(phone, smsMessage);
      console.log("✅ SMS sent successfully to", phone);
    } catch (smsError) {
      console.error("❌ Failed to send SMS:", smsError.message);
    }

    res.status(201).json({
      message: "Recipient registered successfully.",
      recipient: savedRecipient,
    });

  } catch (error) {
    console.error("❌ Error saving recipient:", error.message);
    res.status(500).json({ message: "Error creating recipient", error });
  }
};

// ✅ Get all recipients (admin only)
exports.getAllRecipients = async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Access denied: Admins only" });
    }

    const recipients = await Recipient.find();
    res.status(200).json(recipients);
  } catch (error) {
    console.error("❌ Error retrieving recipients:", error.message);
    res.status(500).json({ message: "Error retrieving recipients", error });
  }
};

// ✅ Get recipient's own record (recipient only)
exports.getMyRecipientRecord = async (req, res) => {
  try {
    const recipient = await Recipient.findOne({ userId: req.user.id });
    if (!recipient) {
      return res.status(404).json({ message: "No recipient record found for this user" });
    }
    res.status(200).json(recipient);
  } catch (error) {
    console.error("❌ Error retrieving recipient record:", error.message);
    res.status(500).json({ message: "Error retrieving recipient record", error });
  }
};
