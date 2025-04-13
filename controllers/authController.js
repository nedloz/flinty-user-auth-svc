const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Auth = require('../collections/Auth');
const UserProfile = require('../collections/UserProfile')
const uuid = require('uuid');
const redisClient = require('../utils/redisClient');
const send2FACodeViaSms = require('../utils/smsService');
const createUserSessionAndIssueTokens = require('../utils/sessionService');
const generate2FACode = require('../utils/twoFactorService');
const logger = require('../utils/logger');
const { error } = require('winston');


// пользователь вводит email, password, username
// после этого вызывается функция register которая создает профиль в auth и user
// после этого пользователю выводится страница где можно указать bio, birthday,
// phone_number и тд. и вызывается функция updateUser и данные пользователя обновляются

const register = async (req, res, next) => {
    try {
        const { email, password, username } = req.body;

        if (!email || !password || !username) {
            const err = new Error('Не хватает полей');
            err.status(400);
            throw err;
        }

        const exists = await Auth.findOne({ email });

        if (exists) {
            const err = new Error(`Пользователь с таким ${email} и ${password} уже существует`);
            err.status = 409;
            throw err;
        }

        const userId = uuid.v4();
        const hashedPassword = await bcrypt.hash(password, 12);

        const user = new Auth({
            user_id: userId,
            email,
            hashed_password: hashedPassword
        });

        await user.save();
        logger.info(`Пользователь ${userId} создан в Auth`);

        const userProfile = new UserProfile({
            user_id: userId,
            email,
            username
        });

        await userProfile.save();

        logger.info(`Профиль пользователя ${userId} сохранен в UserProfile`);

        const tokenResponce = await createUserSessionAndIssueTokens(user, req, res);
        res.status(201).json({
            user_id: userId,
            email,
            username,
            ...tokenResponce
        });
        logger.info(`Токены отправлены пользователю ${user.user_id}`);

    } catch (err) {
        next(err);
    }
}

const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            const err = new Error('Не хватает полей');
            err.statusCode(400);
            throw err;
        }

        const user = await Auth.findOne({ email });

        if (!user) {
            const err = new Error('Неверный email или пароль');
            err.statusCode(401);
            throw err;
        }

        const pwsValid = await bcrypt.compare(password, user.hashed_password);
        if (!pwsValid) {
            const err = new Error('Неверный email или пароль');
            err.statusCode(401);
            throw err;
        }
        if (user.two_factor?.enabled) {
            const code = generate2FACode();
            const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

            user.two_factor.code = code;
            user.two_factor.expires_at = expiresAt;
            await user.save();

            send2FACodeViaSms(user.phone_number, code).catch((err) => {
                logger.error('Ошибка при отправке SMS', { err });
            });
            logger.info(`2FA код пользователя ${user.user_id} создан и отправлен`);
            return res.status(403).json({
                message: '2FA required',
                user_id: user.user_id
            });
        }


        const tokenResponce = await createUserSessionAndIssueTokens(user, req, res);
        res.status(201).json(tokenResponce);
        logger.info(`Токены отправлены пользователю ${user.user_id}`);
    } catch (err) {
        next(err);
    }

}

const verify2FA = async (req, res, next) => {
    try {
        const { user_id, code } = req.body;
        if (!user_id || !code) {
            const err = new Error('Не хватает полей');
            err.statusCode(400);
            throw err;
        }

        const user = await Auth.findOne({ user_id });

        if (!user || !user.two_factor?.enabled) {
            const err = new Error('Двухфакторная аутенификация не активна');
            err.statusCode(400);
            throw err;
        }

        const { two_factor } = user;
        if (!two_factor.code || !two_factor.expires_at) {
            const err = new Error("Код не был сгенерирован");
            err.statusCode(400);
            throw err;
        }

        const now = new Date();

        if (now > new Date(two_factor.expires_at)) {
            const err = new Error("Код истек, запросите новый");
            err.statusCode(400);
            throw err;
        }

        if (two_factor.code !== code) {
            const err = new Error("Неверный код");
            err.statusCode(400);
            throw err; 
        }

        user.two_factor.code = null;
        user.two_factor.expires_at = null;
        user.two_factor.verified_at = now;
        await user.save();
        logger.info(`2FA код пользователя ${user.user_id} верифицирован и удален из бд`);


        const tokenResponce = await createUserSessionAndIssueTokens(user, req, res);
        res.status(201).json(tokenResponce);
        logger.info(`Токены отправлены пользователю ${user.user_id}`);

    } catch (err) {
        next();
    }
}

const refreshToken = async (req, res, next) => {
    try {
        const { refreshToken } = req.cookies;
        if (!refreshToken) {
            const err = new Error("Refresh токен отсутствует");
            err.statusCode(401);
            throw err; 
        }

        let payload;
        try {
            payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            err.statusCode(403);
            next(new Error("Невалидный refresh token"));
        }
        const { user_id, session_id } = payload;
        logger.info(`Refresh токен успешно расшифрован, сессия: ${session_id}`);

        const sessionKey = `session:${user_id}:${session_id}`;
        const session = await redisClient.get(sessionKey);
        if (!session) {
            const err = new Error('Сессия истекла или недействительна');
            err.status(403);
            throw err;
        }
        logger.info(`Cессия ${session_id} найдена`);

        const user = await Auth.findOne({ user_id });
        if (!user) {
            const err = new Error("Пользователь не найден");
            err.statusCode(404);
            throw err; 
        }
        logger.info(`Пользователь ${user.user_id} найден`);

        await redisClient.del(sessionKey);
        await redisClient.sRem(`sessions_of:${user_id}`, session_id);
        logger.info(`Cессия ${payload.session_id} удалена`);

        const tokenResponce = await createUserSessionAndIssueTokens(user, req, res);
        res.status(201).json(tokenResponce);
        logger.info(`Токены отправлены пользователю ${user.user_id}`);
    } catch (err) {
        next(err);
    }
}

const logout = async (req, res, next) => {
    try {
        const { refreshToken } = req.cookies;
        if (!refreshToken) {
            const err = new Error("Refresh токен отсутствует");
            err.statusCode(401);
            throw err; 
        }

        let payload;
        try {
            payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            res.clearCookie('refresh_token');
            err.status(403);
            next(new Error("Невалидный refresh token"));
        }
        const userId = payload.user_id;
        const sessionId = payload.session_id;
        logger.info(`Refresh токен успешно расшифрован, сессия: ${sessionId}`);

        const sessionKey = `session:${userId}:${sessionId}`;
        await redisClient.del(sessionKey);
        await redisClient.sRem(`sessions_of:${userId}`);

        res.clearCookie('refresh_token');
        res.status(200).json({
            message: "Успешный выход из системы"
        })
        logger.info(`Пользователь успешно вышел из системы`);

    } catch (err) {
        next(err);
    }
}

const enable2FA = async (req, res, next) => {
    try {
        const userId = req.user?.user_id;
        const { enabled } = req.body;
        if (typeof enabled !== 'boolean' || !enabled) {
            const err = new Error("В поле enabled было переданно неправильное значение или поле не было переданно");
            err.statusCode(400);
            throw err; 
        }
        if (!userId) {
            const err = new Error("Вы не авторизованы");
            err.statusCode(401);
            throw err; 
        }

        const user = await Auth.findOne({ user_id: userId });
        if (!user) {
            const err = new Error(`Пользователь ${userId} не найден`);
            err.statusCode(404);
            throw err; 
        }

        const now = new Date();

        if (enabled) {
            const code = generate2FACode();
            const expiresAt = new Date(now.getItem() + 5 * 60 * 1000);

            user.two_factor = {
                enabled: true,
                code,
                expires_at: expiresAt,
                verified_at: null
            };

            await user.save();

            res.status(200).json({
                message: "2fa включена"
            });
        } else {
            if (!user.two_factor?.enabled) {
                const err = new Error("2fa уже отключена");
                err.statusCode(400);
                throw err; 
            }

            user.two_factor.enabled = null;
            user.two_factor.code = null;
            user.two_factor.expires_at = null;
            user.two_factor.verified_at = null;
            await user.save();

            res.status(200).json({
                message: "2fa отключена"
            });
        }
    } catch (err) {
        next(err);
    }
}

const request2FACode = async (req, res, next) => {
    try {
        const { user_id } = req.body;

        if (!user_id) {
            const err = new Error('Не указан user_id');
            err.statusCode(400);
            throw err; 
        }

        const user = await Auth.findOne(user_id);
        if (!user) {
            const err = new Error('Пользователь не найден');
            err.statusCode(404);
            throw err; 
        }

        if (!user.two_factor?.enabled) {
            const err = new Error('2fa не включена для этого пользователя');
            err.statusCode(400);
            throw err; 
        }

        const code = generate2FACode();
        const expiresAt = new (Date(Date.now() + 5 * 60 * 1000));

        user.two_factor.code = code;
        user.two_factor.expires_at = expiresAt;

        await user.save();

        res.status(200).json({
            message: 'Новый код подтвержения отправлен'
        })
    } catch (err) {
        next(err);
    }
}

const getUserSessions = async (req, res, next) => {
    try {
        const userId = req.user?.user_id;
        if (!userId) {
            const err = new Error('Пользователь не авторизован');
            err.statusCode(400);
            throw err;
        }

        const sessionIds = await redisClient.sMembers(`sessions_of:${userId}`);
        const sessions = [];

        for (const sessionId of sessionIds) {
            const raw = await redisClient.get(`session:${userId}:${sessionId}`);
            if (!raw) continue;
            try {
                const session = JSON.parse(raw);
                sessions.push({
                    session_id: sessionId,
                    ip: session.ip,
                    device_name: session.device_name,
                    created_at: session.created_at,
                    last_seen_at: session.last_seen_at
                })
            } catch (err) {
                await redisClient.del(`session:${userId}:${sessionId}`);
                await redisClient.sRem(`sessions_of:${userId}`, sessionId);
                logger.err(`${err.method} - ${req.url} данные поврежденной сессии ${sessionId} были удалены`);
            }
        }

        res.json({ sessions });
    } catch (err) {
        next(err);
    }
}

const deleteSessionById = async (req, res, next) => {
    try {
        const userId = req.user?.user_id;
        const sessionId = req.params.id
        if (!userId || !sessionId) {
            const err = new Error('Пользователь не авторизован');
            err.statusCode(400);
            throw err;
        }
        const key = `session:${userId}:${sessionId}`

        const sessionExists = await redisClient.exists(key);
        if (!sessionExists) {
            const err = new Error('Сессия не найдена');
            err.statusCode(404);
            throw err;
        }

        await redisClient.del(key);
        await redisClient.sRem(`sessions_of:${userId}`);
        res.status(200).json({
            message: 'Сессия завершена'
        });
        
    } catch (err) {
        next(err);
    }
}

const deleteAllSessionsExceptCurrent = async (req, res, next) => {
    try {
        const { refreshToken } = req.cookies;
        if (!refreshToken) {
            const err = new Error("Refresh токен отсутствует");
            err.statusCode(401);
            throw err;
        }

        let payload;
        try {
            payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            res.clearCookie('refresh_token');
            err.status(403);
            next(new Error("Невалидный refresh token"));
        }
        const userId = payload.user_id;
        const currentSessionId = payload.session_id;
        logger.info(`Refresh токен успешно расшифрован, сессия: ${currentSessionId}`);

        const sessionIds = await redisClient.sMembers(`sessions_of:${userId}`);
        const toDelete = sessionIds.filter(id => id !== currentSessionId)

        for (const sessionId of toDelete) {
            await redisClient.del(`session:${userId}:${sessionId}`);
            await redisClient.sRem(`sessions_of:${userId}`, sessionId);
        }
        res.status(200).json({
            message: 'Все сессии кроме текущей завершены'
        })
    } catch (err) {
        next(err);
    }
}


module.exports = {
    register,
    login,
    verify2FA,
    refreshToken,
    logout,
    enable2FA,
    request2FACode,
    getUserSessions,
    deleteSessionById,
    deleteAllSessionsExceptCurrent,
}