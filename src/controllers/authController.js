const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Auth = require('../collections/Auth');
const UserProfile = require('../collections/UserProfile')
const uuid = require('uuid');
const redis = require('../utils/redisClient');
const send2FACode = require('../utils/smsService');
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
            err.status = 400;
            throw err;
        }
        const exists = await Auth.findOne({ email });
        if (exists) {
            const err = new Error(`Email уже занят`);
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
        const userProfile = new UserProfile({
            user_id: userId,
            email,
            username
        });
        try {
            await user.save();
            await userProfile.save();
        } catch (err) {
            return next(err);
        }
        logger.info(`Пользователь ${userId} создан в Auth`);
        logger.info(`Профиль пользователя ${userId} сохранен в UserProfile`);
        let tokenResponce;
        try {
            tokenResponce = await createUserSessionAndIssueTokens(user, req, res);
        } catch (err) {
            throw err;
        }
        res.status(201).json({
            user_id: userId,
            email: email,
            username: username,
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
            err.status = 400;
            throw err;
        }
        const user = await Auth.findOne({ email });
        if (!user) {
            const err = new Error('Неверный email или пароль');
            err.status = 401;
            throw err;
        }
        const pwsValid = await bcrypt.compare(password, user.hashed_password);
        if (!pwsValid) {
            const err = new Error('Неверный email или пароль');
            err.status = 401;
            throw err;
        }
        if (user.two_factor?.enabled) {
            const code = generate2FACode();
            const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

            user.two_factor.code = code;
            user.two_factor.expires_at = expiresAt;
            await user.save();

            await send2FACode(user.email, code).catch((err) => {
                logger.error('Ошибка при отправке кода', { err });
                return next(err);
            });
            logger.info(`2FA код пользователя ${user.user_id} создан и отправлен`);
            return res.status(403).json({
                message: '2FA required',
                user_id: user.user_id
            });
        }
        let tokenResponce;
        try {
            tokenResponce = await createUserSessionAndIssueTokens(user, req, res);

        } catch (err) {
            throw err;
        }
        res.status(201).json({
            user_id: user.user_id,
            email: email,
            ...tokenResponce
        });
        logger.info(`Токены отправлены пользователю ${user.user_id}`);
    } catch (err) {
        next(err);
    }
}



const refreshToken = async (req, res, next) => {
    try {
        const { refresh_token } = req.cookies;
        if (!refresh_token) {
            const err = new Error("Refresh токен отсутствует");
            err.status = 401;
            throw err; 
        }

        let payload;
        try {
            payload = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            err.status = 403;
            next(new Error("Невалидный refresh token"));
        }
        const { user_id, session_id } = payload;
        logger.info(`Refresh токен успешно расшифрован, сессия: ${session_id}`);

        const sessionKey = `session:${user_id}:${session_id}`;
        const session = await redis.get(sessionKey);
        if (!session) {
            const err = new Error('Сессия истекла или недействительна');
            err.status = 403;
            throw err;
        }
        logger.info(`Cессия ${session_id} найдена`);

        const user = await Auth.findOne({ user_id });
        if (!user) {
            const err = new Error("Пользователь не найден");
            err.status = 404;
            throw err; 
        }
        logger.info(`Пользователь ${user.user_id} найден`);

        await redis.del(sessionKey);
        await redis.sRem(`sessions_of:${user_id}`, session_id);
        logger.info(`Cессия ${payload.session_id} удалена`);
        try {
            tokenResponce = await createUserSessionAndIssueTokens(user, req, res);
        } catch (err) {
            throw err;
        }
        res.status(201).json(tokenResponce);
        logger.info(`Токены отправлены пользователю ${user.user_id}`);
    } catch (err) {
        next(err);
    }
}

const logout = async (req, res, next) => {
    try {
        const { refresh_token } = req.cookies;
        if (!refresh_token) {
            const err = new Error("Refresh токен отсутствует");
            err.status = 401;
            throw err; 
        }

        let payload;
        try {
            payload = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);
            console.log(payload);
        } catch (err) {
            res.clearCookie('refresh_token');
            err.status = 403;
            return next(err);
        }
        const userId = payload.user_id;
        const sessionId = payload.session_id;
        logger.info(`Refresh токен успешно расшифрован, сессия: ${sessionId}`);

        const sessionKey = `session:${userId}:${sessionId}`;
        await redis.del(sessionKey);
        await redis.sRem(`sessions_of:${userId}`, sessionId);

        res.clearCookie('refresh_token');
        return res.status(200).json({
            message: "Успешный выход из системы"
        })

    } catch (err) {
        next(err);
    }
}

const enable2FA = async (req, res, next) => {
    try {
        const userId = req.user?.user_id;
        const { enabled } = req.body;
        if (typeof enabled !== 'boolean') {
            const err = new Error("В поле enabled было переданно неправильное значение или поле не было переданно");
            err.status = 400;
            throw err; 
        }
        if (!userId) {
            const err = new Error("Вы не авторизованы");
            err.status = 401;
            throw err; 
        }

        const user = await Auth.findOne({ user_id: userId });
        if (!user) {
            const err = new Error(`Пользователь ${userId} не найден`);
            err.status = 404;
            throw err; 
        }

        const now = new Date();

        if (enabled) {
            const code = generate2FACode();
            const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

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
                err.status = 400;
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
            err.status = 400;
            throw err; 
        }

        const user = await Auth.findOne({ user_id });
        if (!user) {
            const err = new Error('Пользователь не найден');
            err.status = 404;
            throw err; 
        }

        if (!user.two_factor?.enabled) {
            const err = new Error('2fa не включена для этого пользователя');
            err.status = 400;
            throw err; 
        }
        logger.info("Все проверки перед генерацией кода сделаны");

        const code = generate2FACode();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        user.two_factor.code = code;
        user.two_factor.expires_at = expiresAt;
        
        await user.save();
        await send2FACode(user.email, code).catch((err) => {
            logger.error('Ошибка при отправке кода', { err });
            return next(err);
        });
        logger.info(`2FA код пользователя ${user.user_id} создан и отправлен`);
        logger.info("Все параметры 2fa кода заданы");

        res.status(200).json({
            message: 'Новый код подтвержения отправлен'
        })
    } catch (err) {
        next(err);
    }
}

const verify2FA = async (req, res, next) => {
    try {
        const { user_id, code } = req.body;
        if (!user_id || !code) {
            const err = new Error('Не хватает полей');
            err.status = 400;
            throw err;
        }
        const user = await Auth.findOne({ user_id });

        if (!user || !user.two_factor?.enabled) {
            const err = new Error('Двухфакторная аутенификация не активна');
            err.status = 400;
            throw err;
        }
        const { two_factor } = user;
        if (!two_factor.code || !two_factor.expires_at) {
            const err = new Error("Код не был сгенерирован");
            err.status = 400;
            throw err;
        }
        const now = new Date();

        if (now > new Date(two_factor.expires_at)) {
            const err = new Error("Код истек, запросите новый");
            err.status = 400;
            throw err;
        }
        console.log(two_factor.code);
        if (two_factor.code !== code) {
            const err = new Error("Неверный код");
            err.status = 400;
            throw err; 
        }

        user.two_factor.code = null;
        user.two_factor.expires_at = null;
        user.two_factor.verified_at = now;
        await user.save();
        logger.info(`2FA код пользователя ${user.user_id} верифицирован и удален из бд`);

        try {
            tokenResponce = await createUserSessionAndIssueTokens(user, req, res);
        } catch (err) {
            throw err;
        }

        res.status(201).json(tokenResponce);
        logger.info(`Токены отправлены пользователю ${user.user_id}`);

    } catch (err) {
        next(err);
    }
}

const getUserSessions = async (req, res, next) => {
    try {
        const userId = req.user?.user_id;
        if (!userId) {
            const err = new Error('Пользователь не авторизован');
            err.status = 400;
            throw err;
        }

        const sessionIds = await redis.sMembers(`sessions_of:${userId}`);
        const sessions = [];

        for (const sessionId of sessionIds) {
            const raw = await redis.get(`session:${userId}:${sessionId}`);
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
                await redis.del(`session:${userId}:${sessionId}`);
                await redis.sRem(`sessions_of:${userId}`, sessionId);
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
            err.status = 400;
            throw err;
        }
        const key = `session:${userId}:${sessionId}`

        const sessionExists = await redis.exists(key);
        if (!sessionExists) {
            const err = new Error('Сессия не найдена');
            err.status = 404;
            throw err;
        }

        await redis.del(key);
        await redis.sRem(`sessions_of:${userId}`, sessionId);
        res.status(200).json({
            message: 'Сессия завершена'
        });
        
    } catch (err) {
        next(err);
    }
}

const deleteAllSessionsExceptCurrent = async (req, res, next) => {
    try {
        const { refresh_token } = req.cookies;
        if (!refresh_token) {
            const err = new Error("Refresh токен отсутствует");
            err.status = 401;
            throw err; 
        }
        let payload;
        try {
            payload = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            res.clearCookie('refresh_token');
            err.status = 403;
            return next(err);
        }
        const userId = payload.user_id;
        const currentSessionId = payload.session_id;
        logger.info(`Refresh токен успешно расшифрован, сессия: ${currentSessionId}`);

        const sessionIds = await redis.sMembers(`sessions_of:${userId}`);
        const toDelete = sessionIds.filter(id => id !== currentSessionId)

        for (const sessionId of toDelete) {
            await redis.del(`session:${userId}:${sessionId}`);
            await redis.sRem(`sessions_of:${userId}`, sessionId);
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