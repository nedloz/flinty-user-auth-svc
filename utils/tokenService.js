const jwt = require('jsonwebtoken');

const generateAccessToken = (user) => {
    return jwt.sign(
        { user_id: user.user_id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
    );
}

const generateRefreshToken = (sessionId) => {
    return jwt.sign(
        { session_id: sessionId },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '30d' }
    )
}

module.exports = {
    generateAccessToken,
    generateRefreshToken
}