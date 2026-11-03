import { createApp } from './app.ts';
import { createContext } from './bootstrap.ts';
import { loadConfig } from './config.ts';
import { createLogger } from './lib/logger.ts';
import { runMaintenance } from './services/maintenance.ts';

const config = loadConfig();
const logger = createLogger(config.logLevel);
const ctx = await createContext(config, logger);
const app = createApp(ctx);

const server = app.listen(config.port, config.host, () => {
  logger.info('dpay backend listening', { host: config.host, port: config.port, env: config.env, attestation: config.attestation.mode });
});

  const maintenance = setInterval(async () => {
    try {
      await runMaintenance(ctx);
    } catch (e) {
      logger.error('maintenance failed', { error: String(e) });
    }
  }, config.maintenanceIntervalSeconds * 1000);
  maintenance.unref();

    async function shutdown(signal: string) {
      logger.info('shutting down', { signal });
      clearInterval(maintenance);
        server.close(async () => {
          try {
            await ctx.db.close();
            await ctx.redis.close();
          } catch {
            // ignore
          }
          process.exit(0);
        });
        setTimeout(() => process.exit(1), 10_000).unref();
      }
process.on('SIGINT', () => shutdown('SIGINT'));
      process.on('SIGTERM', () => shutdown('SIGTERM'));
