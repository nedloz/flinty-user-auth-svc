const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');


router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/refresh', authController.refreshToken);
router.post('/2fa', authController.enable2FA);
router.post('/auth/request-2fa-code', authController.request2FACode);
router.post('/verify-2fa', authController.verify2FA);
router.delete('/auth/sessions/:id', authController.deleteSessionById);
router.delete('/auth/sessions', authController.deleteAllSessionsExceptCurrent);

module.exports = router;