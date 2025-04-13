const logger = require('../utils/logger');
const errorHandler = (err, req, res, next) => {
    logger.error(`[${err.method}] - ${req.url}  ${err.message}`);
    res.status(err.status || 500).json({
        error: {
            message: err.message,
            code: statusCode
        }
    });
}
module.exports = errorHandler;