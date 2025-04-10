const UserProfile = require('../collections/UserProfile');
const logger = require('../utils/logger');


// const createUser = async (req, res, next) => {
//     try {
//         const user = new UserProfile(req.body);
//         await user.save();
//         res.status(201).json(user);
//         logger.info(`Пользователь ${user.user_id} создан`)
//     } catch (e) {
//         next(e);
//     }
// }

const getUser = async(req, res, next) => {
    try {
        const user = await UserProfile.findOne(req.body);
        if (!user) {
            res.status(404);
            throw new Error('Пользователь не найден');
        }
        res.json(user);
        logger.info(`Данные пользователя ${user.user_id} отправлены`);
    } catch (err) {
        next(err);
    }
}

// дописать логику сохранения картинок
const updateUser = async(req, res, next) => {
    try {
        const user = await UserProfile.findOneAndUpdate(
            { ...req.body, updated_at: new Date() },
            { new: true }
        );
        if (!user) {
            res.status(404);
            throw new Error("Пользователь не найден");
        }
        res.json(user);
        logger.info(`Данные пользователя ${user.user_id} обновлены`);

    } catch (err) {
        next(err);
    }
}

const deleteUser = async (req, res, next) => {
    try {
        const result = await UserProfile.findOneAndDelete(req.body);
        if (!result) {
            res.status(404);
            throw new Error(`Ошибка удаления пользователя ${ req.body }`);
        }
        res.status(204).send();
    } catch (err) {
        next(err);
    }
}

module.exports = {
    getUser,
    updateUser,
    deleteUser
}
