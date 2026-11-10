import cors from 'cors';
import express, { type Express } from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';
import { openApiSpec, openApiYaml } from './docs/openapi.ts';
import { BankError, BankException } from './domain/errors.ts';
import { Limits } from './domain/limits.ts';
import { errorHandler, requestLogger, requireSession } from './http/middleware.ts';
import { adminRoutes } from './http/routes/admin.ts';
import { authRoutes } from './http/routes/auth.ts';
import { bankRoutes } from './http/routes/bank.ts';
import { deviceRoutes, handleRoutes, profileRoutes } from './http/routes/profile.ts';
import { settlementRoutes } from './http/routes/settlement.ts';
import { provisioningRoutes, walletRoutes } from './http/routes/wallet.ts';
import type { ServiceContext } from './services/context.ts';

export function createApp(ctx: ServiceContext): Express {
  const app = express();
  app.disable('x-powered-by');
  const tp = ctx.config.trustProxy;
  if (tp) {
    app.set('trust proxy', /^\d+$/.test(tp) ? Number(tp) : tp === 'true' ? 1 : tp);
  } else {
    app.set('trust proxy', 1);
  }

  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors({ origin: ctx.config.corsOrigins ? [...ctx.config.corsOrigins] : false }));
  app.use(requestLogger(ctx.logger));
  app.use(
    rateLimit({
      windowMs: 60 * 1000,
      limit: ctx.config.env === 'test' ? 100_000 : 300,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      validate: {
        trustProxy: false,
        xForwardedForHeader: false,
      },
      message: { error: { code: BankError.RATE_LIMITED, message: 'too many requests' } },
    }),
  );
  // Body size: only the routes that carry certificates or payments need megabytes, and those all
  // require a session. Everything else (including every unauthenticated route) gets a small limit,
  // so an anonymous caller cannot make the server buffer and parse large JSON bodies.
  // Settlement uploads: up to 200 payments of a few KB each, base64 encoded.
  const largeJson = express.json({ limit: `${Math.ceil((Limits.MAX_SETTLEMENT_ITEMS * 5 * 1024 * 4) / 3 / 1024 / 1024) + 1}mb` });
  const smallJson = express.json({ limit: '16kb' });
  const LARGE_BODY_ROUTES = new Set(['/v1/settlement', '/v1/wallet/certificate', '/v1/wallet/notes']);
  const session = requireSession(ctx);
  app.use((req, res, next) => {
    if (!LARGE_BODY_ROUTES.has(req.path.replace(/\/+$/, ''))) return smallJson(req, res, next);
    // Authenticate before reading a large body.
    void session(req, res, (err?: unknown) => (err ? next(err) : largeJson(req, res, next)));
  });

  // Swagger Documentation & OpenAPI Endpoints: a full map of the API, so off by default in production.
  if (ctx.config.exposeApiDocs) {
    app.get('/docs/openapi.json', (_req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.send(JSON.stringify(openApiSpec, null, 2));
    });

    app.get('/docs/openapi.yaml', (_req, res) => {
      res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
      res.send(openApiYaml);
    });

    app.use(
      '/docs',
      swaggerUi.serve,
      swaggerUi.setup(openApiSpec, {
        customSiteTitle: 'DPay API Documentation (Swagger)',
        customCss: '.swagger-ui .topbar { display: none }',
      }),
    );
    app.get('/api-docs', (_req, res) => {
      res.redirect('/docs');
    });
  }

  /** Liveness probe: returns 200 if the HTTP process is running. */
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'dpay-backend',
      version: '0.1.0',
      uptimeSeconds: Math.floor(process.uptime()),
      time: ctx.clock(),
    });
  });

  /** Readiness probe: returns 200 if DB, Redis, and Issuer key are operational; 503 otherwise. */
  app.get('/health/ready', async (_req, res) => {
    const [dbOk, redisOk] = await Promise.all([ctx.db.ping(), ctx.redis.ping()]);
    const issuerOk = ctx.issuer.keyId > 0;
    const ready = dbOk && redisOk && issuerOk;

    const body = {
      status: ready ? 'ready' : 'unhealthy',
      checks: {
        database: dbOk ? 'up' : 'down',
        redis: redisOk ? 'up' : 'down',
        issuerKey: issuerOk ? 'loaded' : 'missing',
      },
      time: ctx.clock(),
    };

    res.status(ready ? 200 : 503).json(body);
  });

  const v1 = express.Router();
  /** Issuer keys the app pins (BankApi.trustAnchors). Pin them at build time; this is for tooling. */
  v1.get('/trust-anchors', (_req, res) => {
    res.json({ issuers: ctx.issuer.describeTrustAnchors() });
  });
  v1.use('/auth', authRoutes(ctx));
  v1.use('/handles', handleRoutes(ctx));
  v1.use('/profile', profileRoutes(ctx));
  v1.use('/device', deviceRoutes(ctx));
  v1.use('/provisioning', provisioningRoutes(ctx));
  v1.use('/wallet', walletRoutes(ctx));
  v1.use('/admin', adminRoutes(ctx));
  // Central Bank Simulator (RBI / Interbank Clearing): mounted at both /bank and /central-bank
  v1.use('/bank', bankRoutes(ctx));
  v1.use('/central-bank', bankRoutes(ctx));
  v1.use('/', settlementRoutes(ctx));
  app.use('/v1', v1);

  app.use((_req, _res) => {
    throw new BankException(BankError.NOT_FOUND, 'no such endpoint');
  });
  app.use(errorHandler(ctx.logger));
  return app;
}
