const Donor = require("../models/Donor");
const sendSMS = require("../utils/sendSMS");

// ✅ Create donor (must be logged in as donor role)
exports.createDonor = async (req, res) => {
  try {
    if (req.user.role !== "donor") {
      return res.status(403).json({ message: "Access denied: Donor role required" });
    }

    const donorData = {
      userId: req.user.id,
      name: req.body.name,
      address: req.body.address,
      gender: req.body.gender,
      age: req.body.age,
      phone_no: req.body.phone_no,
      bloodType: req.body.bloodType,
      organ: req.body.organ,
      donor_id: req.body.donor_id
    };

    const savedDonor = await Donor.create(donorData);
    console.log("✅ Donor saved:", savedDonor);

    let phone = req.body.phone_no.replace(/\D/g, "");
    if (!phone.startsWith("91")) {
      phone = "91" + phone;
    }
    phone = "+" + phone;
    console.log("📞 Sending SMS to:", phone);

    const smsMessage = `🙏 Hello ${req.body.name}, thank you for registering as a donor for ${req.body.organ} on OrganHub. Your contribution can save lives!`;

    try {
      await sendSMS(phone, smsMessage);
      console.log("✅ SMS sent successfully to", phone);
    } catch (smsError) {
      console.error("❌ Failed to send SMS:", smsError.message);
    }

    res.status(201).json({
      message: "Donor registered successfully.",
      donor: savedDonor,
    });

  } catch (error) {
    console.error("❌ Donor creation error:", error.message);
    res.status(500).json({ message: "Error creating donor", error });
  }
};

// ✅ Admin: Get all donors
exports.getAllDonors = async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Access denied: Admins only" });
    }

    const donors = await Donor.find();
    res.status(200).json(donors);
  } catch (error) {
    console.error("❌ Error retrieving donors:", error.message);
    res.status(500).json({ message: "Error retrieving donors", error });
  }
};

// ✅ Donor: Get own donor record
exports.getMyDonorRecord = async (req, res) => {
  try {
    if (req.user.role !== "donor") {
      return res.status(403).json({ message: "Access denied: Donor role required" });
    }

    const donor = await Donor.findOne({ userId: req.user.id });
    if (!donor) {
      return res.status(404).json({ message: "No donor record found for this user" });
    }

    res.status(200).json(donor);
  } catch (error) {
    console.error("❌ Error retrieving donor record:", error.message);
    res.status(500).json({ message: "Error retrieving donor record", error });
  }
};

