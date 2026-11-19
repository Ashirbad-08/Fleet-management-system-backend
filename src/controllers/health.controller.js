import asyncHandler from '../utils/asyncHandler.js';
import * as healthService from '../services/health.service.js';

const getHealth = asyncHandler(async (req, res) => {
  const health = healthService.getHealth();
  const statusCode = health.status === 'ok' ? 200 : 503;

  res.status(statusCode).json({ success: statusCode === 200, data: health });
});

export { getHealth };
