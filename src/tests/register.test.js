const request = require('supertest');
const express = require('express');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const authRoutes = require('../routes/authRoutes');
const Auth = require('../collections/Auth'); // твоя модель пользователя

const app = express();
app.use(express.json());
app.use('/auth', authRoutes);

let mongoServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
});

afterEach(async () => {
  await Auth.deleteMany();
});

describe('POST /auth/register', () => {
  it('успешная регистрация', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({
        "email": "email@email.com",
        "password": "12345"
    });
    console.log(res.message);
    expect(res.statusCode).toBe(201);
    expect(res.body.expires_in).toBe(900);
  });

  // it('регистрация с уже существующей почтой', async () => {
  //   await Auth.create({
  //     email: 'test@example.com',
  //     password: 'hashedpassword' // заранее хешированный пароль
  //   });

  //   const res = await request(app)
  //     .post('/auth/register')
  //     .send({
  //       email: 'test@example.com',
  //       password: 'Another123!'
  //     });

  //   expect(res.statusCode).toBe(409);
  // });

  // it('регистрация без email', async () => {
  //   const res = await request(app)
  //     .post('/auth/register')
  //     .send({ password: 'Test1234!' });

  //   expect(res.statusCode).toBe(400);
  // });

  // it('регистрация с невалидным email', async () => {
  //   const res = await request(app)
  //     .post('/auth/register')
  //     .send({
  //       email: 'invalidemail',
  //       password: 'Test1234!'
  //     });

  //   expect(res.statusCode).toBe(400);
  // });
});
