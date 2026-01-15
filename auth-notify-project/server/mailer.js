const nodemailer = require("nodemailer");

function makeTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

async function sendMail(to, subject, text) {
  const transporter = makeTransport();
  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to,
    subject,
    text,
  });
}

module.exports = { sendMail };
