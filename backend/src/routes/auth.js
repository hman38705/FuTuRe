import express from 'express';
import { body, validationResult } from 'express-validator';
import { hashPassword, verifyPassword } from '../auth/password.js';
import { createUser, findUser, getUserById, updateUserPassword } from '../auth/userStore.js';
import { signAccessToken, signRefreshToken, verifyToken } from '../auth/tokens.js';
import { requireAuth } from '../middleware/auth.js';
import { consumePendingCredentials } from '../recovery/recoveryStore.js';
import { createRateLimiter } from '../middleware/rateLimiter.js';
import { recordFailedLogin, isAccountLocked, unlockAccount, clearFailedAttempts, getLockoutDuration } from '../security/accountLockout.js';
import { getClientIP } from '../middleware/rateLimiter.js';
import logger from '../config/logger.js';

const router = express.Router();

const validateBody = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });
  next();
};

const userRules = [
  body('username').trim().isLength({ min: 3, max: 32 }).withMessage('Username must be 3-32 chars'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 chars'),
];

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [username, password]
 *             properties:
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 32
 *               password:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       201:
 *         description: User created
 *       409:
 *         description: Username already taken
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       422:
 *         description: Validation error
 */
router.post('/register', userRules, validateBody, async (req, res) => {
  try {
    const { username, password } = req.body;
    const passwordHash = await hashPassword(password);
    const user = createUser(username, passwordHash);
    res.status(201).json({ user });
  } catch (error) {
    res.status(409).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Log in and receive JWT tokens
 *     tags: [Auth]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [username, password]
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Tokens issued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken: { type: string }
 *                 refreshToken: { type: string }
 *                 recovered: { type: boolean }
 *       401:
 *         description: Invalid credentials
 *       423:
 *         description: Account locked
 *       422:
 *         description: Validation error
 */
const loginRateLimiter = createRateLimiter({
  windowMs: 60000,
  max: 10,
  message: 'Too many login attempts, please try again later.',
});

router.post('/login', loginRateLimiter, userRules, validateBody, async (req, res) => {
  const { username, password } = req.body;
  const ipAddress = getClientIP(req);

  // Check if account is locked
  const locked = await isAccountLocked(username);
  if (locked) {
    const retryAfter = Math.ceil(getLockoutDuration() / 1000);
    return res.status(423).set('Retry-After', retryAfter).json({
      error: 'Account is temporarily locked due to too many failed login attempts',
      retryAfter,
    });
  }

  const user = findUser(username);
  if (!user) {
    await recordFailedLogin(username, ipAddress);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Check for pending recovered credentials first
  const recovered = consumePendingCredentials(user.id);
  if (recovered) {
    const valid = await verifyPassword(password, recovered.passwordHash);
    if (valid) {
      updateUserPassword(user.id, recovered.passwordHash);
      await clearFailedAttempts(username);
      const payload = { sub: user.id, username: user.username };
      return res.json({
        accessToken: signAccessToken(payload),
        refreshToken: signRefreshToken(payload),
        recovered: true,
      });
    }
    await recordFailedLogin(username, ipAddress);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!(await verifyPassword(password, user.passwordHash))) {
    await recordFailedLogin(username, ipAddress);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Successful login - clear failed attempts
  await clearFailedAttempts(username);
  const payload = { sub: user.id, username: user.username };
  res.json({
    accessToken: signAccessToken(payload),
    refreshToken: signRefreshToken(payload),
  });
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Auth]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [refreshToken]
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: New access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken: { type: string }
 *       400:
 *         description: refreshToken missing
 *       401:
 *         description: Invalid or expired refresh token
 */
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });
  try {
    const { sub, username } = verifyToken(refreshToken);
    res.json({ accessToken: signAccessToken({ sub, username }) });
  } catch {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Log out (client should discard tokens)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out
 *       401:
 *         description: Unauthorized
 */
router.post('/logout', requireAuth, (_req, res) => {
  res.json({ message: 'Logged out successfully' });
});

/**
 * @swagger
 * /api/auth/profile:
 *   get:
 *     summary: Get authenticated user profile
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id: { type: string }
 *                 username: { type: string }
 *                 createdAt: { type: string, format: date-time }
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 */
router.get('/profile', requireAuth, (req, res) => {
  const user = getUserById(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, createdAt: user.createdAt });
});

/**
 * @swagger
 * /api/auth/admin/unlock:
 *   post:
 *     summary: Admin endpoint to manually unlock an account
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [username]
 *             properties:
 *               username:
 *                 type: string
 *     responses:
 *       200:
 *         description: Account unlocked
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden (not admin)
 */
router.post('/admin/unlock', requireAuth, async (req, res) => {
  const { username } = req.body;
  
  // Check if user is admin (simplified - in production use proper role checking)
  const user = getUserById(req.user.sub);
  if (!user?.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    await unlockAccount(username);
    logger.info({ admin: user.username, unlocked: username }, 'Account unlocked by admin');
    res.json({ message: `Account ${username} has been unlocked` });
  } catch (err) {
    logger.error({ err, username }, 'Failed to unlock account');
    res.status(500).json({ error: 'Failed to unlock account' });
  }
});

export default router;
