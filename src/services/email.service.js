import nodemailer from 'nodemailer';

const isConfigured = () => Boolean(
  process.env.SMTP_HOST
  && process.env.SMTP_USER
  && process.env.SMTP_PASSWORD
  && process.env.MAIL_FROM
  && process.env.APP_URL,
);

const assertEmailConfigured = () => {
  if (!isConfigured()) {
    const error = new Error('Email is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD, MAIL_FROM, and APP_URL.');
    error.statusCode = 503;
    throw error;
  }
};

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[character]));

const sendAccountCredentialsEmail = async ({ to, name, password, subject = 'Your account details', message = 'Your account has been created. Use these details to sign in:' }) => {
  assertEmailConfigured();
  const port = Number(process.env.SMTP_PORT || 587);
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: process.env.SMTP_SECURE === 'true' || port === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD },
  });
  const loginUrl = process.env.APP_URL;
  const safeName = escapeHtml(name);
  const safeUrl = escapeHtml(loginUrl);
  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: `Electrie Fleet Management System | ${subject}`,
    text: `Electrie Fleet Management System\n\nHello ${name},\n\n${message}\nUser ID: ${to}\nPassword: ${password}\nWebsite: ${loginUrl}\n\nSecurity caution: Do not share this email or your login details with anyone.`,
    html: `<div style="font-family:Arial,sans-serif;color:#1f2937;max-width:600px;margin:auto"><div style="background:#12304a;padding:24px;color:#fff"><h1 style="margin:0;font-size:22px">Electrie Fleet Management System</h1></div><div style="padding:24px"><p>Hello ${safeName},</p><p>${escapeHtml(message)}</p><div style="background:#f3f6f8;border:1px solid #dbe3e8;padding:16px;border-radius:4px"><p style="margin:4px 0"><strong>User ID:</strong> ${escapeHtml(to)}</p><p style="margin:4px 0"><strong>Password:</strong> ${escapeHtml(password)}</p></div><p style="margin:28px 0"><a href="${safeUrl}" style="background:#167d9a;color:#fff;padding:12px 20px;text-decoration:none;border-radius:4px">Open the website</a></p><p style="color:#9a3412"><strong>Security caution:</strong> Do not share this email or your login details with anyone.</p></div></div>`,
  });
};

const sendPasswordResetOtpEmail = async ({ to, name, otp }) => {
  assertEmailConfigured();
  const port = Number(process.env.SMTP_PORT || 587);
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: process.env.SMTP_SECURE === 'true' || port === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD },
  });
  const safeName = escapeHtml(name);
  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: 'Electrie Fleet Management System | Password reset code',
    text: `Electrie Fleet Management System\n\nHello ${name},\n\nYour password reset code is: ${otp}\nIt expires in 10 minutes and can be used once.\n\nSecurity caution: Do not share this code or this email with anyone. If you did not request a password reset, you can ignore this email.`,
    html: `<div style="font-family:Arial,sans-serif;color:#1f2937;max-width:600px;margin:auto"><div style="background:#12304a;padding:24px;color:#fff"><h1 style="margin:0;font-size:22px">Electrie Fleet Management System</h1></div><div style="padding:24px"><p>Hello ${safeName},</p><p>Use this code to reset your password. It expires in 10 minutes and can be used once.</p><p style="font-size:28px;font-weight:bold;letter-spacing:6px;background:#f3f6f8;padding:16px;text-align:center">${otp}</p><p style="color:#9a3412"><strong>Security caution:</strong> Do not share this code or this email with anyone.</p><p>If you did not request a password reset, you can ignore this email.</p></div></div>`,
  });
};

export { assertEmailConfigured, sendAccountCredentialsEmail, sendPasswordResetOtpEmail };
