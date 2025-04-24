const UserProfile = require('../collections/UserProfile');
const logger = require('../utils/logger');
const Auth = require('../collections/Auth');
const redis  = require('../utils/redisClient');

const getUser = async(req, res, next) => {
    try {
        const userId = req.user?.user_id;
        console.log('getuser', userId);
        if (!userId) {
            const err = new Error('Пользователь не авторизован');
            err.status = 400;
            throw err;
        }

        const user = await UserProfile.findOne({ user_id: userId });
        const authUser = await Auth.findOne({ user_id: userId });
        if (!user) {
            const err = new Error('Пользователь не найден');
            err.status = 404;
            throw err;
        }

        res.json({
            user_id: userId,
            username: user.username,
            email: user.email,
            phone_number: user.phone_number,
            avatar_url: user.avatar_url,
            bio: user.bio,
            birthdate: user.birthdate,
            created_at: user.created_at,
            updated_at: user.updated_at,
            is_2fa_enabled: authUser.two_factor?.enabled
        });
        logger.info(`Данные пользователя ${userId} отправлены`);
    } catch (err) {
        next(err);
    }
}

// дописать логику сохранения картинок
const updateUser = async(req, res, next) => {
    try {
        const userId = req.user?.user_id;
        if (!userId) {
            const err = new Error('Пользователь не авторизован');
            err.status = 400;
            throw err;
        }
        
        const user = await UserProfile.findOneAndUpdate(
            { user_id: userId },
            { ...req.body, updated_at: new Date() },
            { new: true }
        );
        if (!user) {
            const err = new Error('Пользователь не найден');
            err.status = 404;
            throw err;
        }
        res.json({
            message: "Данные пользователя успешно обновлены"
        });
        logger.info(`Данные пользователя ${userId} обновлены`);
    } catch (err) {
        next(err);
    }
}

const deleteUser = async (req, res, next) => {
    try {
        const userId = req.user?.user_id;
        const code = req.body?.code;
        if (!userId) {
            const err = new Error('Пользователь не авторизован');
            err.status = 400;
            throw err;
        }

        const user = await Auth.findOne({ user_id: userId });
        if (!user) {
          const err = new Error('Пользователь не найден');
          err.status = 404;
          throw err;
        }

        
        if (user.two_factor?.enabled) {
            const { two_factor } = user;
    
            if (!code || String(code) !== String(two_factor.code)) {
                const err = new Error('Неверный или отсутствующий 2FA код');
                err.status = 403;
                throw err;
            }
    
            const now = new Date();
            const expiresAt = new Date(two_factor.expires_at);
            if (now > expiresAt) {
                const err = new Error('Код 2FA истёк');
                err.status = 403;
                throw err;
            }
        }
        
        await UserProfile.deleteOne({ user_id: userId });
        await Auth.deleteOne({ user_id: userId });

        const sessionIds = await redis.sMembers(`sessions_of:${userId}`);
        if (sessionIds.length > 0) {
            const keys = sessionIds.map(id => `session:${userId}:${id}`);
            await redis.del(...keys);
        }
        await redis.del(`sessions_of:${userId}`);

        res.clearCookie('refresh_token', {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
            path: '/',
        });
        res.status(200).json({
            message: 'Аккаунт удалён' 
        });
    } catch (err) {
        next(err);
    }
}

module.exports = {
    getUser,
    updateUser,
    deleteUser
}
