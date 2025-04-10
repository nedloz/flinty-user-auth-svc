const uuid = require('uuid');
const redisClient = require('redis');
const logger = require('./logger');
const { generateAccessToken, generateRefreshToken } = require('./tokenService');
const setRefreshCookie = require('./cookieService');
const parceUserAgent = require('./uaParser');


const createUserSessionAndIssueTokens = async (user, req, res) => {
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];
    const sessionId = uuid.v4();

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(sessionId);

    await redisClient.setEx(
        `refresh:session:${sessionId}`,
        60 * 60 * 24 * 10,
        JSON.stringify({
            user_id: user.user_id,
            ip,
            user_agent: userAgent,
            device_name: parceUserAgent(userAgent),
            created_at: new Date.toISOString(),
            last_seen_at: new Date.toISOString(),
        })
    );
    logger.info(`Сессия пользователя ${user.user_id} сохранена в redis`);

    setRefreshCookie(res, refreshToken);

    return {
        access_token: accessToken,
        expires_in: 900
    };
}

module.exports = createUserSessionAndIssueTokens;