const app = require('./app');
const env = require('./config/env');
const { seed } = require('./seed');
const { cleanupExpired } = require('./utils/tokens');

seed({ quiet: false });                        // idempotent: creates test accounts if missing
setInterval(cleanupExpired, 60 * 60 * 1000).unref();

app.listen(env.PORT, () => {
  console.log(`Security Gateway running on ${env.APP_URL} (port ${env.PORT}, ${env.NODE_ENV})`);
  console.log(`GitHub OAuth: ${env.GITHUB_CLIENT_ID ? 'enabled' : 'NOT configured (set GITHUB_CLIENT_ID/SECRET)'}`);
});
