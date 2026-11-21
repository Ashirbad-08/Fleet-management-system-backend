import express from 'express';
import asyncHandler from '../utils/asyncHandler.js';
import * as controller from '../controllers/admin.controller.js';
import { authenticate, allowRoles } from '../middlewares/auth.middleware.js';
const router = express.Router();
const adminRouter = express.Router();

/**
 * @swagger
 * /api/auth/bootstrap-super-admin:
 *   post:
 *     summary: Create the first super admin
 *     description: Requires the SUPER_ADMIN_SETUP_KEY in the x-setup-key header. Available only before a super admin exists.
 *     tags: [Authentication]
 *     parameters:
 *       - in: header
 *         name: x-setup-key
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password]
 *             properties:
 *               name: { type: string, minLength: 6, maxLength: 20 }
 *               email: { type: string, format: email }
 *               password: { type: string, minLength: 6, description: Must include uppercase, lowercase, number, and special character }
 *     responses:
 *       201:
 *         description: Super admin created; an HttpOnly authentication cookie is set
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/AuthResponse' }
 *       403: { description: Invalid setup key }
 *       409: { description: Super admin is already configured }
 */
router.post('/auth/bootstrap-super-admin', asyncHandler(controller.bootstrap));

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Sign in
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string, format: email }
 *               password: { type: string }
 *     responses:
 *       200:
 *         description: Signed in; an HttpOnly authentication cookie is set
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/AuthResponse' }
 *       401: { description: Invalid credentials }
 */
router.post('/auth/login', asyncHandler(controller.login));

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request an email password reset code
 *     description: Sends a single-use code to active admin and superadmin accounts and sets a short-lived HttpOnly reset-session cookie. Operators are directed to contact an admin; unregistered emails receive an invalid-email response.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email: { type: string, format: email }
 *     responses:
 *       200: { description: Reset code sent or recently sent }
 *       403: { description: Operator or inactive account cannot use this flow }
 *       404: { description: No account is registered with this email }
 */
router.post('/auth/forgot-password', asyncHandler(controller.requestPasswordResetOtp));

/**
 * @swagger
 * /api/auth/reset-password-otp:
 *   post:
 *     summary: Reset an admin or superadmin password using an email code
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [otp, newPassword, confirmPassword]
 *             properties:
 *               otp: { type: string, pattern: '^[0-9]{6}$' }
 *               newPassword: { type: string, minLength: 6, description: Must include uppercase, lowercase, number, and special character }
 *               confirmPassword: { type: string }
 *     responses:
 *       200: { description: Password changed and active sessions revoked }
 *       400: { description: Invalid, expired, or exhausted code; or passwords do not match }
 */
router.post('/auth/reset-password-otp', asyncHandler(controller.resetPasswordWithOtp));

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Get the current account
 *     tags: [Authentication]
 *     security: [{ bearerAuth: [] }, { cookieAuth: [] }]
 *     responses:
 *       200:
 *         description: Current account
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 data: { $ref: '#/components/schemas/Account' }
 *       401: { description: Authentication required }
 */
router.get('/auth/me', authenticate, asyncHandler(controller.me));

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Log out the current account
 *     description: Revokes all active tokens for the authenticated account and clears the authentication cookie. Sign in again to start a new session.
 *     tags: [Authentication]
 *     security: [{ bearerAuth: [] }, { cookieAuth: [] }]
 *     responses:
 *       200: { description: Tokens revoked }
 *       401: { description: Authentication required }
 */
router.post('/auth/logout', authenticate, asyncHandler(controller.logout));

adminRouter.use(authenticate);

/**
 * @swagger
 * /api/admins/{id}/password-reset:
 *   post:
 *     summary: Set a new operator password
 *     description: Admins and superadmins can set an operator password. The new credentials are emailed to the operator and active sessions are revoked.
 *     tags: [Administration]
 *     security: [{ bearerAuth: [] }, { cookieAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [password, confirmPassword]
 *             properties:
 *               password: { type: string, minLength: 6, description: Must include uppercase, lowercase, number, and special character }
 *               confirmPassword: { type: string }
 *     responses:
 *       200: { description: Operator password changed and emailed }
 *       403: { description: Operator is outside the caller's depot access }
 */
adminRouter.post('/:id/password-reset', allowRoles('super_admin','admin'), asyncHandler(controller.setOperatorPassword));

adminRouter.get('/', allowRoles('super_admin', 'admin'), asyncHandler(controller.list));
/**
 * @swagger
 * /api/admins:
 *   post:
 *     summary: Create an admin or operator account
 *     description: Emails the supplied password and APP_URL website link to the new user's email address.
 *     tags: [Administration]
 *     security: [{ bearerAuth: [] }, { cookieAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password, role]
 *             properties:
 *               name: { type: string, minLength: 6, maxLength: 20 }
 *               email: { type: string, format: email, description: Also used as the user ID }
 *               phone: { type: string, description: Optional phone number }
 *               password: { type: string, minLength: 6, description: Must include uppercase, lowercase, number, and special character }
 *               role: { type: string, enum: [admin, operator] }
 *               depotIds: { type: array, items: { type: string } }
 *               sendEmail: { type: boolean, default: true, description: Send login details by email. Set false to skip email delivery. }
 *     responses:
 *       201: { description: Account created; email delivery is optional and runs in the background }
 *       400: { description: Invalid request data }
 *       503: { description: Email is enabled but required email settings are missing }
 */
adminRouter.post('/', allowRoles('super_admin', 'admin'), asyncHandler(controller.create));
/**
 * @swagger
 * /api/admins/{id}:
 *   patch:
 *     summary: Edit a user account
 *     description: Admins can manage users within their depot access; superadmins can manage all users. Email and passwords cannot be changed through this endpoint.
 *     tags: [Administration]
 *     security: [{ bearerAuth: [] }, { cookieAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name: { type: string, minLength: 6, maxLength: 20 }
 *               phone: { type: string, description: Empty string clears the phone number }
 *               role: { type: string, enum: [admin, operator] }
 *               depotIds: { type: array, items: { type: string } }
 *               active: { type: boolean }
 *     responses:
 *       200: { description: User updated }
 *       400: { description: Invalid request data }
 *       403: { description: User is outside the caller's permissions }
 *   delete:
 *     summary: Delete a user account
 *     tags: [Administration]
 *     security: [{ bearerAuth: [] }, { cookieAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: User deleted }
 *       403: { description: User is outside the caller's permissions }
 */
adminRouter.patch('/:id', allowRoles('super_admin', 'admin'), asyncHandler(controller.update));
adminRouter.delete('/:id', allowRoles('super_admin', 'admin'), asyncHandler(controller.remove));

router.use('/admins', adminRouter);

export default router;
