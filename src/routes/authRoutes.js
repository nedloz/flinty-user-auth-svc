const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validateAccessToken } = require('../controllers/validateAccessToken');

router.get('/validate', validateAccessToken);

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/refresh', authController.refreshToken);
router.post('/2fa', authController.enable2FA);
router.post('/request-2fa-code', authController.request2FACode);
router.post('/verify', authController.verify2FA);
router.get('/sessions', authController.getUserSessions);
router.delete('/sessions/:id', authController.deleteSessionById);
router.delete('/sessions', authController.deleteAllSessionsExceptCurrent);

module.exports = router;