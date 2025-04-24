const { createClient } = require('redis');

const redis = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redis.on('error', err => console.error('❌ Redis error', err));
redis.on('connect', () => console.log('✅ Redis connected'));

(async () => {
  await redis.connect();
})();

module.exports = redis;