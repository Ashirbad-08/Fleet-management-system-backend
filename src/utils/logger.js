import path from 'node:path';
import { fileURLToPath } from 'node:url';
import winston from 'winston';
import { env, logLevel } from '../config/env.js';

const { combine, timestamp, printf, colorize, errors, json } = winston.format;

const consoleFormat = combine(
  colorize(),
  timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  errors({ stack: true }),
  printf(({ timestamp, level, message, stack }) => `${timestamp} ${level}: ${stack || message}`)
);

const fileFormat = combine(timestamp(), errors({ stack: true }), json());

const logDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'logs');

const logger = winston.createLogger({
  level: logLevel,
  transports: [
    new winston.transports.Console({
      format: consoleFormat,
      silent: env === 'test',
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      format: fileFormat,
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
      format: fileFormat,
    }),
  ],
  exitOnError: false,
});

export default logger;
