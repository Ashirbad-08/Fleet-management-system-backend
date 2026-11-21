import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, minlength: 6, maxlength: 20 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, match: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/ },
  phone: { type: String, trim: true, maxlength: 25, default: '' },
  passwordHash: { type: String, required: true, select: false },
  role: { type: String, enum: ['super_admin', 'admin', 'operator'], required: true },
  depotIds: [{ type: String, trim: true }],
  tokenVersion: { type: Number, default: 0 },
  active: { type: Boolean, default: true },
  passwordResetOtp: {
    codeHash: { type: String, default: '' },
    tempTokenHash: { type: String, default: '' },
    attempts: { type: Number, default: 0 },
    lastSentAt: { type: Date },
    expiresAt: { type: Date },
  },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
export default User;
