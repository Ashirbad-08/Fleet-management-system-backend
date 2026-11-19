import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET must be configured in production');
}
const secret = process.env.JWT_SECRET || 'development-only-change-this-secret';

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `${salt}:${derived.toString('hex')}`;
}

async function verifyPassword(password, stored) {
  const [salt, hash] = (stored || '').split(':');
  if (!salt || !hash) return false;
  const expected = Buffer.from(hash, 'hex');
  const actual = await scrypt(password, salt, expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function signToken(user) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const head = encode({ alg: 'HS256', typ: 'JWT' });
  const body = encode({ sub: user._id.toString(), role: user.role, tokenVersion: user.tokenVersion || 0, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60 * 60 * 12 });
  const input = `${head}.${body}`;
  const signature = crypto.createHmac('sha256', secret).update(input).digest('base64url');
  return `${input}.${signature}`;
}

function verifyToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const input = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac('sha256', secret).update(input).digest();
  let actual;
  try { actual = Buffer.from(parts[2], 'base64url'); } catch (_) { return null; }
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return payload.exp > Math.floor(Date.now() / 1000) ? payload : null;
  } catch (_) { return null; }
}

export { hashPassword, verifyPassword, signToken, verifyToken };
