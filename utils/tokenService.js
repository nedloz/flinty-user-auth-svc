const jwt = require('jsonwebtoken');

const generateAccessToken = (user) => {
    return jwt.sign(
        { user_id: user.user_id, email: user.email },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: '15m' }
    );
}

const generateRefreshToken = (user, sessionId) => {
    return jwt.sign(
        { user_id: user.user_id, session_id: sessionId },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '30d' }
    )
}

module.exports = {
    generateAccessToken,
    generateRefreshToken
}