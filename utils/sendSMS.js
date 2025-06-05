const twilio = require("twilio");
const accountSid = process.env.TWILIO_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const fromPhone = process.env.TWILIO_PHONE;

const client = twilio(accountSid, authToken);

const sendSMS = async (to, body) => {
  try {
    console.log("📲 Sending SMS to:", to);
    console.log("📩 Message body:", body);
    const message = await client.messages.create({
      body,
      from: fromPhone,
      to,
    });
    console.log("✅ SMS sent successfully. SID:", message.sid);
  } catch (err) {
    console.error("❌ Failed to send SMS to:", to, "Error:", err.message);
    throw err;
  }
};

module.exports = sendSMS;
