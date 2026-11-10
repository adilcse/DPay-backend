module.exports = {
  apps: [
    {
      name: 'dpay-backend',
      script: 'dist/index.js',
      node_args: '--env-file=.env',
      watch: false,
      autorestart: true,
      max_memory_restart: '1G',
      // NODE_ENV is deliberately not set here: it comes from .env. Forcing "development" switched off
      // the production start-up checks (attestation, issuer key, debug OTP) without anyone noticing.
    },
  ],
};
