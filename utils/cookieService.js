const logger = require('./logger');
const setRefreshCookie = (res, token) => {
    res.cookie('refresh_token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: 1000 * 60 * 60 * 24 * 10
    });
    logger.info(`Refresh токен пользователя ${user.user_id} сохранен в куки`);
};

module.exports = setRefreshCookie;