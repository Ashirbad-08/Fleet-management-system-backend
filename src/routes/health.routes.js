import express from 'express';
import { getHealth } from '../controllers/health.controller.js';

const router = express.Router();

/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Health check
 *     description: Returns server status, uptime and MongoDB connection state.
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Server and database are healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     status:
 *                       type: string
 *                       example: ok
 *                     uptime:
 *                       type: integer
 *                       example: 120
 *                     timestamp:
 *                       type: string
 *                       format: date-time
 *                     database:
 *                       type: string
 *                       example: connected
 *       503:
 *         description: Database is not connected
 */
router.get('/', getHealth);

export default router;
