import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';

import swaggerSpec from './config/swagger.js';
import routes from './routes/index.js';
import { notFound, errorConverter, errorHandler } from './middlewares/error.middleware.js';

const app = express();

const configuredOrigins = [process.env.APP_URL, ...(process.env.CORS_ORIGINS || '').split(',')]
  .filter(Boolean)
  .map((value) => {
    try { return new URL(value.trim()).origin; } catch { return value.trim(); }
  });
const allowedOrigins = new Set(configuredOrigins);

// Security & parsing
app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || process.env.NODE_ENV !== 'production' || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// API documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Root status endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Backend API is running successfully!',
    status: 'OK',
    website: 'https://fleet.electrie.in',
    documentation: 'https://fleet-api.electrie.in/docs',
  });
});

// Routes
app.use('/api', routes);

// Error handling (must be last)
app.use(notFound);
app.use(errorConverter);
app.use(errorHandler);

export default app;
