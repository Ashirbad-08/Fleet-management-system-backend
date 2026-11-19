import express from 'express';
import healthRoutes from './health.routes.js';
import adminRoutes from './admin.routes.js';
import permissionRoutes from './permission.routes.js';

const router = express.Router();

router.use('/health', healthRoutes);
router.use(adminRoutes);
router.use('/permissions', permissionRoutes);

export default router;
