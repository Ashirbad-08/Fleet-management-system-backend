import express from 'express';
import asyncHandler from '../utils/asyncHandler.js';
import * as controller from '../controllers/permission.controller.js';
import { authenticate } from '../middlewares/auth.middleware.js';
const router = express.Router();

/**
 * @swagger
 * /api/permissions/me:
 *   get:
 *     summary: Get the current account's role permissions and scope
 *     tags: [Authorization]
 *     security: [{ bearerAuth: [] }]
 *     responses:
 *       200:
 *         description: Permissions and depot scope
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 data:
 *                   type: object
 *                   properties:
 *                     role: { type: string, enum: [super_admin, admin, operator] }
 *                     depotIds: { type: array, items: { type: string } }
 *                     permissions: { type: array, items: { type: string } }
 *       401: { description: Authentication required }
 */
router.get('/me', authenticate, asyncHandler(controller.me));
export default router;
