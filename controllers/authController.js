const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Auth = require('../collections/Auth');
const UserProfile = require('../collections/UserProfile')
const uuid = require('uuid');
const redisClient = require('../utils/redisClient');
const send2FACodeViaSms = require('../utils/smsService');
const createUserSessionAndIssueTokens = require('../utils/sessionService');
const generate2FACode = require('../utils/twoFactorService');



// пользователь вводит email, password, username
// после этого вызывается функция register которая создает профиль в auth и user
// после этого пользователю выводится страница где можно указать bio, birthday,
// phone_number и тд. и вызывается функция updateUser и данные пользователя обновляются

const register = async (req, res, next) => {
    try {
        const { email, password, username } = req.body;
        const exists = Auth.findOne({ email });

        if (exists) {
            res.status(409);
            throw new Error("Пользователь с таким email уже существует");
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
        res.status(201).json({
            user_id: userId,
            email,
            username
        })
        logger.info(`Профиль пользователя ${userId} сохранен в UserProfile`);
        
        const tokenResponce = await createUserSessionAndIssueTokens(user, req, res);
        res.status(201).json(tokenResponce);
        logger.info(`Токены отправлены пользователю ${user.user_id}`);
        
    } catch (err) {
        next(err);
    }
}

const login = async (req, res, next) => {
    try {
        const { email, pws } = req.body;
        const user = await Auth.findOne({ email });

        if (!user) {
            res.status(401);
            throw new Error('Неверный email или пароль');
        }

        const pwsValid = await bcrypt.compare(pws, user.password);
        if (!pwsValid) {
            res.status(401);
            throw new Error('Неверный email или пароль');
        }
        if (user.two_factor?.enabled) {
            const code = generate2FACode();
            const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

            user.two_factor.code = code;
            user.two_factor.expires_at = expiresAt;
            await user.save();

            await send2FACodeViaSms(user.phone_number, code);
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
        const user = await Auth.findOne({ user_id });

        if (!user || !user.two_factor?.enabled) {
            res.status(400);
            throw new Error('Двухфакторная аутенификация не активна');
        }

        const { two_factor } = user;
        if (!two_factor.code || !two_factor.expires_at) {
            res.status(400);
            throw new Error("Код не был сгенерирован");
        }

        const now = new Date();

        if (now > new Date(two_factor.expires_at)) {
            res.status(400);
            throw new Error("Код истек, запросите новый");
        }

        if (two_factor.code !== code) {
            res.status(400);
            throw new Error("Неверный код");
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
            res.status(401);
            throw new Error("Refresh токен отсутствует");
        }

        let payload;

        try {
            payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            res.status(403);
            next(new Error("Невалидный refresh token"));
        }
        logger.info(`Refresh токен успешно расшифрован, сессия: ${payload.session_id}`);

        const sessionKey = `refresh:session:${payload.session_id}`;
        const session = await redisClient.get(sessionKey);
        logger.info(``);
        
        if (!session) {
            res.status(403);
            throw new Error('Сессия не найдена или истекла');
        }
        logger.info(`Cессия ${payload.session_id} найдена`);

        const sessionData = JSON.parce(session);
        const user = await Auth.findOne({ user_id: sessionData.user_id });

        if (!user) {
            res.status(404);
            throw new Error("Пользователь не найден");
        }
        logger.info(`Пользователь ${user.user_id} найден`);

        await redisClient.del(sessionKey);
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
            res.status(401);
            throw new Error("Refresh токен отсутствует");
        }

        let payload;
        try {
            payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            res.clearCookie('refresh_token');
            res.status(403);
            next(new Error("Невалидный refresh token"));
        }
        logger.info(`Refresh токен успешно расшифрован, сессия: ${payload.session_id}`);

        const sessionKey = `refresh:session:${payload.session_id}`;
        await redisClient.del(sessionKey);
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
            res.status(400);
            throw new Error("В поле enabled было переданно неправильное значение или поле не было переданно");
        }
        if (!userId) {
            res.status(401);
            throw new Error("Вы не авторизованы");
        }

        const user = await Auth.findOne({ user_id: userId });
        if (!user) {
            res.status(404);
            throw new Error(`Пользователь ${userId} не найден`);
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
                res.status(400);
                throw new Error("2fa уже отключена");
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


// post /auth/login
// post /auth/verify-2fa
// post /auth/refresh
// post /auth/logout
// post /auth/register
// patch /auth/2fa
// post /auth/request-2fa-code
// get /users/me
// patch /users/me
// get /auth/sessions 
// delete /auth/sessions 

// generateAccesToken(user)
// generateRefreshToken(session_id)
// generate2FACode()
// storeRefreshToken(session_id, user_id, ttl)
// getRefreshToken(session_id)
// revokeRefreshToken(session_id)
// listUserSessions(user_id)
// revokeAllSessionsExcept(user_id, current_session_id)





module.exports = {
    register,
    login,
    verify2FA,
    refreshToken,
    logout,


}