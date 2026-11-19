import mongoose from 'mongoose';

const passwordResetOtpSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  codeHash: { type: String, required: true },
  tempTokenHash: { type: String, default: '' },
  attempts: { type: Number, default: 0 },
  lastSentAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true, expires: 0 },
}, { timestamps: true });

const PasswordResetOtp = mongoose.model('PasswordResetOtp', passwordResetOtpSchema);
export default PasswordResetOtp;
