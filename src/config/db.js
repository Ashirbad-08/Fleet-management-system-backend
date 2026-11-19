import mongoose from 'mongoose';
import { MONGO_URI } from './env.js';
import logger from '../utils/logger.js';

mongoose.connection.on('connected', () => logger.info('MongoDB connected'));
mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'));
mongoose.connection.on('error', (err) => logger.error(`MongoDB error: ${err.message}`));

const connectDB = async () => {
  await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 5000,
  });
};

const disconnectDB = async () => {
  await mongoose.connection.close();
};

export { connectDB, disconnectDB };
