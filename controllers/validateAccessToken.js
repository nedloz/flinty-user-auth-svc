const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

const validateAccessToken = (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn('Попытка доступа без токена или с неверным заголовком', {
            ip: req.ip,
            url: req.originalUrl,
            headers: req.headers
          });
        return res.sendStatus(401);
    }

    const token = authHeader.split(' ')[1];

    try {
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        res.set('X-User-Id', payload.user_id);
        return res.sendStatus(200);
    } catch (err) {
        logger.error('Невалидный access token', {
            error: err.message,
            ip: req.ip,
            token: token.slice(0, 10) + '...',
        });
        return res.sendStatus(401);
    }
}

module.exports = { validateAccessToken };