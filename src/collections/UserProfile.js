const mongoose = require("mongoose");

const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
const phoneRegex = /^\+?[1-9]\d{1,14}$/;

const ProfileSchema = new mongoose.Schema({
    user_id: { type: String, required: true, unique: true },
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true, 
        validate: {
            validator: function (v) {
                return emailRegex.test(v);
            },
            message: props => `${props.value} - Неккоректный email`
        }
     },
    phone_number: { type: String, unique: true, 
        validate: {
            validator: function (v) {
                return phoneRegex.test(v);
            },
            message: props => `${props.value} - неккоректный номер`
        }
    },
    avatar_url: String,
    bio: String,
    birthdate: Date, 
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now } 
});

module.exports = mongoose.model('userProfile', ProfileSchema);
