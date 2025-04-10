const UserProfile = require('../collections/UserProfile');
const logger = require('../utils/logger');
const Auth = require('../collections/Auth');
const redisClient = require('../utils/redisClient');

const getUser = async(req, res, next) => {
    try {
        const userId = req.user?.user_id;
        if (!userId) {
            res.status(400);
            throw new Error('Пользователь не авторизован');
        }

        const user = await UserProfile.findOne({ user_id: userId });
        const authUser = await Auth.findOne({ user_id: userId });
        if (!user) {
            res.status(404);
            throw new Error('Пользователь не найден');
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
            res.status(400);
            throw new Error('Пользователь не авторизован');
        }
        const user = await UserProfile.findOneAndUpdate(
            { ...req.body, updated_at: new Date() },
            { new: true }
        );
        if (!user) {
            res.status(404);
            throw new Error('Пользователь не найден');
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
        if (!userId) {
            res.status(400);
            throw new Error('Пользователь не авторизован');
        }
        await UserProfile.deleteOne({ user_id: userId });
        await Auth.deleteOne({ user_id: userId });

        const sessionIds = await redisClient.sMembers(`sessions_of:${userId}`);
        for (const sessionId of sessionIds) {
            await redisClient.del(`session:${userId}:${sessionId}`);
          }
        await redisClient.del(`sessions_of:${userId}`);
        res.clearCookie('refresh_token');
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
