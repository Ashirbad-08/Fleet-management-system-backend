import mongoose from 'mongoose';
import ApiError from '../utils/ApiError.js';
import logger from '../utils/logger.js';
import { env } from '../config/env.js';

// 404 for unknown routes
const notFound = (req, res, next) => {
  next(new ApiError(404, `Route not found: ${req.method} ${req.originalUrl}`));
};

// Normalizes any thrown error into an ApiError
const errorConverter = (err, req, res, next) => {
  let error = err;

  if (!(error instanceof ApiError)) {
    let statusCode = error.statusCode || 500;
    let message = error.message || 'Internal Server Error';

    if (error instanceof mongoose.Error.CastError) {
      statusCode = 400;
      message = `Invalid ${error.path}: ${error.value}`;
    } else if (error instanceof mongoose.Error.ValidationError) {
      statusCode = 400;
      message = Object.values(error.errors).map((e) => e.message).join(', ');
    } else if (error.code === 11000) {
      statusCode = 409;
      message = `Duplicate value for: ${Object.keys(error.keyValue || {}).join(', ')}`;
    } else if (error.type === 'entity.parse.failed') {
      statusCode = 400;
      message = 'Invalid JSON body';
    }

    error = new ApiError(statusCode, message, statusCode < 500, err.stack);
  }

  next(error);
};

// Final error handler
// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message =
    env === 'production' && !err.isOperational ? 'Internal Server Error' : err.message;

  const logMessage = `${req.method} ${req.originalUrl} - ${statusCode} - ${err.message}`;
  if (statusCode >= 500) {
    logger.error(`${logMessage}\n${err.stack}`);
  } else {
    logger.warn(logMessage);
  }

  res.status(statusCode).json({
    success: false,
    message,
    ...(env === 'development' && { stack: err.stack }),
  });
};

export { notFound, errorConverter, errorHandler };
