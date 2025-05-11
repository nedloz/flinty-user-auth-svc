const { createClient } = require('redis');

const redis = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redis.on('error', err => logger.error(`❌ Redis error: \t ${err}`));
redis.on('connect', () => logger.info('✅ Redis connected'));

(async () => {
  await redis.connect();
})();

module.exports = redis;