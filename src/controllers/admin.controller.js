import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import User from '../models/User.js';
import ApiError from '../utils/ApiError.js';
import { hashPassword, verifyPassword, signToken } from '../utils/auth.js';
import { isValidEmail, isValidName, isValidPassword, isValidPhone } from '../utils/validation.js';
import PasswordResetOtp from '../models/PasswordResetOtp.js';
import { assertEmailConfigured, sendAccountCredentialsEmail, sendPasswordResetOtpEmail } from '../services/email.service.js';
import logger from '../utils/logger.js';

const validRoles = ['super_admin', 'admin', 'operator'];
const otpCooldownMs = 60 * 1000;
const otpLifetimeMs = 10 * 60 * 1000;
const otpMaxAttempts = 5;
const resetCookieName = 'passwordResetTempToken';
const resetCookiePath = '/api/auth/reset-password-otp';
const resetCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: resetCookiePath,
  maxAge: otpLifetimeMs,
};
const otpHash = (userId, otp) => createHmac('sha256', process.env.JWT_SECRET || 'development-only-change-this-secret')
  .update(`${userId}:${otp}`)
  .digest('hex');
const getCookie = (req, name) => {
  const cookie = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return cookie ? cookie.slice(name.length + 1) : '';
};
const publicUser = (user) => ({ id: user._id, name: user.name, email: user.email, phone: user.phone, role: user.role, depotIds: user.depotIds, active: user.active });

const bootstrap = async (req, res) => {
  const setupKey = process.env.SUPER_ADMIN_SETUP_KEY;
  if (!setupKey || req.get('x-setup-key') !== setupKey) throw new ApiError(403, 'Invalid setup key');
  if (await User.exists({ role: 'super_admin' })) throw new ApiError(409, 'Super admin is already configured');
  const { name, email, password } = req.body;
  if (!isValidName(name)) throw new ApiError(400, 'Name must be between 6 and 20 characters');
  if (!isValidEmail(email)) throw new ApiError(400, 'A valid email address is required');
  if (!isValidPassword(password)) throw new ApiError(400, 'Password must be at least 6 characters and include uppercase, lowercase, number, and special character');
  const user = await User.create({ name: name.trim(), email: email.trim().toLowerCase(), passwordHash: await hashPassword(password), role: 'super_admin' });
  res.status(201).json({ success: true, data: publicUser(user), token: signToken(user) });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) throw new ApiError(400, 'email and password are required');
  const user = await User.findOne({ email: String(email).toLowerCase().trim() }).select('+passwordHash');
  if (!user || !user.active || !(await verifyPassword(password, user.passwordHash))) throw new ApiError(401, 'Invalid email or password');
  res.json({ success: true, data: publicUser(user), token: signToken(user) });
};

const me = async (req, res) => res.json({ success: true, data: publicUser(req.user) });

const logout = async (req, res) => {
  await User.updateOne({ _id: req.user._id }, { $inc: { tokenVersion: 1 } });
  res.json({ success: true, message: 'Logged out successfully. All active tokens for this account have been revoked.' });
};

const hasDepotAccess = (user, depotIds) => user.depotIds.includes('*') || depotIds.some((id) => user.depotIds.includes(id));
const isDepotAllowed = (user, depotId) => user.depotIds.includes('*') || user.depotIds.includes(depotId);
const list = async (req, res) => {
  const query = req.user.role === 'admin'
    ? { role: { $ne: 'super_admin' }, ...(req.user.depotIds.includes('*') ? {} : { depotIds: { $in: req.user.depotIds } }) }
    : {};
  const users = await User.find(query).sort({ name: 1 });
  res.json({ success: true, data: users.map((user) => {
    const item = publicUser(user);
    if (req.user.role === 'admin' && !req.user.depotIds.includes('*')) item.depotIds = item.depotIds.filter((id) => req.user.depotIds.includes(id));
    return item;
  }) });
};

const create = async (req, res) => {
  const { name, email, password, phone, role, depotIds } = req.body;
  if (!isValidName(name)) throw new ApiError(400, 'Name must be between 6 and 20 characters');
  if (!isValidEmail(email)) throw new ApiError(400, 'A valid email address is required');
  if (!isValidPassword(password)) throw new ApiError(400, 'Password must be at least 6 characters and include uppercase, lowercase, number, and special character');
  if (phone !== undefined && !isValidPhone(phone)) throw new ApiError(400, 'A valid phone number is required');
  if (depotIds !== undefined && (!Array.isArray(depotIds) || depotIds.some((id) => typeof id !== 'string' || !id.trim()))) throw new ApiError(400, 'depotIds must be an array of non-empty strings');
  const assignedDepotIds = depotIds ?? (
    req.user.role === 'admin'
      ? [...req.user.depotIds]
      : role === 'admin' ? ['*'] : []
  );
  if (!validRoles.includes(role) || (role === 'super_admin' && req.user.role !== 'super_admin')) throw new ApiError(400, 'Invalid role');
  if (role === 'admin' && req.user.role === 'admin' && assignedDepotIds.some((id) => !isDepotAllowed(req.user, id))) throw new ApiError(403, 'Cannot assign an unassigned depot');
  if (role === 'super_admin') throw new ApiError(400, 'Super admin accounts cannot be created through this endpoint');
  assertEmailConfigured();
  const user = await User.create({ name: name.trim(), email: email.trim().toLowerCase(), phone: phone?.trim() || '', passwordHash: await hashPassword(password), role, depotIds: assignedDepotIds });
  try {
    await sendAccountCredentialsEmail({ to: user.email, name: user.name, password });
  } catch (error) {
    await User.deleteOne({ _id: user._id });
    logger.error('Account credentials email delivery failed', {
      code: error.code,
      command: error.command,
      responseCode: error.responseCode,
      message: error.message,
    });
    throw new ApiError(502, 'Unable to send the account login details. Check the email service configuration.');
  }
  res.status(201).json({ success: true, data: publicUser(user), message: 'Account created. Login details were emailed to the user.' });
};

const requestPasswordResetOtp = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (!isValidEmail(email)) throw new ApiError(400, 'A valid email address is required');
  const user = await User.findOne({ email });
  if (!user) throw new ApiError(404, 'Invalid email address. No account is registered with this email.');
  if (user.role === 'operator') throw new ApiError(403, 'Operators cannot reset their password here. Please contact your admin.');
  if (!['admin', 'super_admin'].includes(user.role)) throw new ApiError(400, 'This account cannot reset its password here.');
  if (!user.active) throw new ApiError(403, 'This account is inactive. Please contact your administrator.');

  const now = new Date();
  const existingOtp = await PasswordResetOtp.findOne({ userId: user._id });
  if (existingOtp && now - existingOtp.lastSentAt < otpCooldownMs) {
    return res.json({ success: true, message: 'A reset code was recently sent to your email. Please check your inbox.' });
  }

  const temporaryToken = randomBytes(32).toString('base64url');
  const tempTokenHash = createHash('sha256').update(temporaryToken).digest('hex');
  res.cookie(resetCookieName, temporaryToken, resetCookieOptions);
  const otp = randomInt(0, 1_000_000).toString().padStart(6, '0');
  const codeHash = otpHash(user._id, otp);
  await PasswordResetOtp.findOneAndUpdate(
    { userId: user._id },
    { userId: user._id, codeHash, tempTokenHash, attempts: 0, lastSentAt: now, expiresAt: new Date(now.getTime() + otpLifetimeMs) },
    { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
  );
  try {
    assertEmailConfigured();
    await sendPasswordResetOtpEmail({ to: user.email, name: user.name, otp });
  } catch (error) {
    await PasswordResetOtp.deleteOne({ userId: user._id, codeHash });
    logger.error('Password reset OTP email delivery failed', {
      code: error.code,
      command: error.command,
      responseCode: error.responseCode,
      message: error.message,
    });
    throw new ApiError(502, 'Unable to send the password reset code. Check the email service configuration.');
  }
  res.json({ success: true, message: 'A password reset code has been sent to your email.' });
};

const resetPasswordWithOtp = async (req, res) => {
  const { otp, newPassword, confirmPassword } = req.body;
  if (typeof otp !== 'string' || !/^\d{6}$/.test(otp)) throw new ApiError(400, 'A valid six-digit reset code is required');
  if (!isValidPassword(newPassword)) throw new ApiError(400, 'Password must be at least 6 characters and include uppercase, lowercase, number, and special character');
  if (newPassword !== confirmPassword) throw new ApiError(400, 'Password confirmation does not match');
  const temporaryToken = getCookie(req, resetCookieName);
  if (!temporaryToken) throw new ApiError(400, 'Password reset session is missing or has expired');
  const tempTokenHash = createHash('sha256').update(temporaryToken).digest('hex');
  const resetOtp = await PasswordResetOtp.findOne({ tempTokenHash, expiresAt: { $gt: new Date() }, attempts: { $lt: otpMaxAttempts } });
  if (!resetOtp) throw new ApiError(400, 'Reset code is invalid or has expired');
  const submittedHash = otpHash(resetOtp.userId, otp);
  const submittedBuffer = Buffer.from(submittedHash, 'hex');
  const storedBuffer = Buffer.from(resetOtp.codeHash, 'hex');
  if (submittedBuffer.length !== storedBuffer.length || !timingSafeEqual(submittedBuffer, storedBuffer)) {
    await PasswordResetOtp.updateOne({ _id: resetOtp._id }, { $inc: { attempts: 1 } });
    if (resetOtp.attempts + 1 >= otpMaxAttempts) await PasswordResetOtp.deleteOne({ _id: resetOtp._id });
    throw new ApiError(400, 'Reset code is invalid or has expired');
  }
  const consumedOtp = await PasswordResetOtp.findOneAndDelete({
    _id: resetOtp._id,
    codeHash: submittedHash,
    expiresAt: { $gt: new Date() },
    attempts: { $lt: otpMaxAttempts },
  });
  if (!consumedOtp) throw new ApiError(400, 'Reset code is invalid or has expired');
  const user = await User.findOne({ _id: resetOtp.userId, active: true, role: { $in: ['admin', 'super_admin'] } });
  if (!user) throw new ApiError(400, 'Reset code is invalid or has expired');
  user.passwordHash = await hashPassword(newPassword);
  user.tokenVersion += 1;
  await user.save();
  const clearCookieOptions = { ...resetCookieOptions };
  delete clearCookieOptions.maxAge;
  res.clearCookie(resetCookieName, clearCookieOptions);
  res.json({ success: true, message: 'Password updated. Please sign in with your new password.' });
};

const setOperatorPassword = async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) throw new ApiError(404, 'User not found');
  if (user.role !== 'operator') throw new ApiError(400, 'This password reset flow is only available for operator accounts');
  if (!user.active) throw new ApiError(400, 'Cannot reset the password for an inactive account');
  if (req.user.role === 'admin' && !hasDepotAccess(req.user, user.depotIds)) throw new ApiError(403, 'Cannot manage this user');
  const { password, confirmPassword } = req.body;
  if (!isValidPassword(password)) throw new ApiError(400, 'Password must be at least 6 characters and include uppercase, lowercase, number, and special character');
  if (password !== confirmPassword) throw new ApiError(400, 'Password confirmation does not match');
  assertEmailConfigured();
  const previousPasswordHash = user.passwordHash;
  const previousTokenVersion = user.tokenVersion;
  user.passwordHash = await hashPassword(password);
  user.tokenVersion += 1;
  await user.save();
  await PasswordResetOtp.deleteOne({ userId: user._id });
  try {
    await sendAccountCredentialsEmail({
      to: user.email,
      name: user.name,
      password,
      subject: 'Your password has been reset',
      message: 'Your administrator has reset your account password. Use these details to sign in:',
    });
  } catch (error) {
    user.passwordHash = previousPasswordHash;
    user.tokenVersion = previousTokenVersion;
    await user.save();
    logger.error('Operator password email delivery failed', {
      code: error.code,
      command: error.command,
      responseCode: error.responseCode,
      message: error.message,
    });
    throw new ApiError(502, 'Unable to send the operator password. Check the email service configuration.');
  }
  res.json({ success: true, message: 'Operator password updated and emailed to the operator.' });
};

const update = async (req, res) => {
  const target = await User.findById(req.params.id);
  if (!target) throw new ApiError(404, 'User not found');
  if (req.user.role === 'admin' && (target.role === 'super_admin' || !hasDepotAccess(req.user, target.depotIds))) throw new ApiError(403, 'Cannot manage this user');
  const { name, email, phone, role, depotIds, active } = req.body;
  if (name !== undefined && !isValidName(name)) throw new ApiError(400, 'Name must be between 6 and 20 characters');
  if (email !== undefined) throw new ApiError(400, 'Email cannot be changed');
  if (phone !== undefined && !isValidPhone(phone)) throw new ApiError(400, 'A valid phone number is required');
  if (req.body.password !== undefined) throw new ApiError(400, 'Use the password recovery flow to change a password');
  if (depotIds !== undefined && (!Array.isArray(depotIds) || depotIds.some((id) => typeof id !== 'string' || !id.trim()))) throw new ApiError(400, 'depotIds must be an array of non-empty strings');
  if (role && (!validRoles.includes(role) || (role === 'super_admin' && req.user.role !== 'super_admin'))) throw new ApiError(400, 'Invalid role');
  if (target.role === 'super_admin' && (role && role !== 'super_admin' || active === false) && await User.countDocuments({ role: 'super_admin', active: true }) <= 1) throw new ApiError(400, 'Cannot remove the last active super admin');
  if (target._id.equals(req.user._id) && (role && role !== req.user.role || active === false)) throw new ApiError(400, 'Cannot deactivate or change your own role');
  if (req.user.role === 'admin' && depotIds && depotIds.some((id) => !isDepotAllowed(req.user, id))) throw new ApiError(403, 'Cannot assign an unassigned depot');
  if (name !== undefined) target.name = name.trim();
  if (phone !== undefined) target.phone = phone.trim();
  if (role !== undefined) target.role = role;
  if (depotIds !== undefined) target.depotIds = depotIds;
  if (active !== undefined) target.active = active;
  await target.save();
  if (active === false || role !== undefined) {
    await PasswordResetOtp.deleteOne({ userId: target._id });
  }
  res.json({ success: true, data: publicUser(target) });
};

const remove = async (req, res) => {
  const target = await User.findById(req.params.id);
  if (!target) throw new ApiError(404, 'User not found');
  if (target._id.equals(req.user._id)) throw new ApiError(400, 'Cannot delete your own account');
  if (req.user.role === 'admin' && (target.role === 'super_admin' || !hasDepotAccess(req.user, target.depotIds))) throw new ApiError(403, 'Cannot manage this user');
  if (target.role === 'super_admin' && await User.countDocuments({ role: 'super_admin', active: true }) <= 1) throw new ApiError(400, 'Cannot delete the last active super admin');
  await PasswordResetOtp.deleteOne({ userId: target._id });
  await target.deleteOne();
  res.json({ success: true, message: 'User deleted' });
};

export { bootstrap, login, me, logout, requestPasswordResetOtp, resetPasswordWithOtp, setOperatorPassword, publicUser, list, create, update, remove };
