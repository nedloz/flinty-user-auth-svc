const uuid = require('uuid');
const redis  = require('./redisClient');
const logger = require('./logger');
const { generateAccessToken, generateRefreshToken } = require('./tokenService');
const setRefreshCookie = require('./cookieService');
const parceUserAgent = require('./uaParser');

const SESSION_TTL = 60 * 60 * 24 * 30;

const createUserSessionAndIssueTokens = async (user, req, res) => {
    try {
        if (!user) {
            const err = Error("User не найден");
            err.status = 400;
            throw err;
        }
        const ip = req.ip;
        const userAgent = req.headers['user-agent'];
        const sessionId = uuid.v4();
        const userId = user.user_id;

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user, sessionId);

        const sessionData = {
            ip,
            user_agent: userAgent,
            device_name: parceUserAgent(userAgent),
            created_at: new Date().toISOString(),
            last_seen_at: new Date().toISOString(),
        }

        await redis.setEx(
            `session:${userId}:${sessionId}`,
            SESSION_TTL,
            JSON.stringify(sessionData)
        );
        await redis.sAdd(`sessions_of:${userId}`, sessionId);
        
        logger.info(`Сессия пользователя ${userId} сохранена в redis`);

        setRefreshCookie(res, refreshToken);

        return {
            access_token: accessToken,
            expires_in: 900
        };  
    } catch (err) {
        return err;
    }
}

module.exports = createUserSessionAndIssueTokens;