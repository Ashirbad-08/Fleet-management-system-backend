import User from '../models/User.js';
import ApiError from '../utils/ApiError.js';
import { verifyToken } from '../utils/auth.js';

const authenticate = async (req, res, next) => {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const payload = verifyToken(token);
    if (!payload) throw new ApiError(401, 'Authentication required');
    const user = await User.findById(payload.sub);
    if (!user || !user.active) throw new ApiError(401, 'Account is unavailable');
    if ((payload.tokenVersion ?? 0) !== (user.tokenVersion ?? 0)) throw new ApiError(401, 'Token has been revoked');
    req.user = user;
    next();
  } catch (error) { next(error); }
};

const allowRoles = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) return next(new ApiError(403, 'Insufficient permissions'));
  next();
};

export { authenticate, allowRoles };
