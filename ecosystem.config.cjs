module.exports = {
  apps: [
    {
      name: 'dpay-backend',
      script: 'dist/index.js',
      node_args: '--env-file=.env',
      watch: false,
      autorestart: true,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'development',
      },
    },
  ],
};
