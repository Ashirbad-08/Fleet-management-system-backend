import 'dotenv/config';

export const env = process.env.NODE_ENV || 'development';
export const port = parseInt(process.env.PORT, 10) || 5000;
export const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/node_mvc_starter';
export const logLevel = process.env.LOG_LEVEL || 'info';
