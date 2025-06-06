const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.get('/', userController.getUser);
router.patch('/', userController.updateUser);
router.delete('/', userController.deleteUser);

module.exports = router;