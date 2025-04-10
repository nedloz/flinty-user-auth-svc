const mongoose = require('mongoose');

const twoFactorSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: false },
    code: String,
    expires_at: Date,
    verified_at: Date,
}, { _id: false});


const AuthShema = new mongoose.Schema({
    user_id: { 
        type: String,  
        unique: true,
        required: true
    },
    email: { type: String, required: true, unique: true, 
        validate: {
            validator: function (v) {
                return emailRegex.test(v);
            },
            message: props => `${props.value} - Неккоректный email`
        }
    },
    hashed_password: { type: String, required: true },
    two_factor: twoFactorSchema, 
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now }
})

module.exports = mongoose.model('Auth', AuthShema);
