const logger = require('../utils/logger');
const errorHandler = (err, req, res, next) => {
    logger.error(`[${err.method}] - ${req.url}  ${err.message}`);
    const statusCode = res.statusCode !== 200 ? res.statusCode : 500;
    res.status(statusCode).json({
        error: {
            message: err.message,
            code: statusCode
        }
    });
}
module.exports = errorHandler;