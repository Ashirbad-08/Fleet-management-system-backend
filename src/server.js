import app from './app.js';
import { port } from './config/env.js';
import { connectDB, disconnectDB } from './config/db.js';
import logger from './utils/logger.js';

let server;

const start = async () => {
  try {
    await connectDB();
    server = app.listen(port, () => {
      logger.info(`Server running on http://localhost:${port}`);
      logger.info(`Swagger docs at http://localhost:${port}/api-docs`);
    });
  } catch (err) {
    logger.error(`Failed to start server: ${err.message}`);
    process.exit(1);
  }
};

const shutdown = async (signal) => {
  logger.info(`${signal} received. Shutting down gracefully...`);
  if (server) {
    server.close(async () => {
      await disconnectDB();
      logger.info('Server closed');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  logger.error(`Unhandled Rejection: ${reason instanceof Error ? reason.stack : reason}`);
  shutdown('unhandledRejection');
});

process.on('uncaughtException', (err) => {
  logger.error(`Uncaught Exception: ${err.stack}`);
  process.exit(1);
});

start();
