require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const usersRoutes = require('./routes/userRoutes');
const authRoutes = require
const logger = require('./utils/logger');

const app = express();
app.use(express.json());

app.use('/auth', authRoutes);
app.use('/users', usersRoutes);

(async () => {
    try { 
        await mongoose.connect(process.env.MONGO_URI);
        app.listen(3000, () => console.log('Сервер запущен на порту: 3000'));

    } catch (err) {
        logger.error('Ошибка подключения к mongoDB: ' + err.message);
        process.exit(1);
    }
})();
