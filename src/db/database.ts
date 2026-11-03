import { AsyncLocalStorage } from 'node:async_hooks';
import pg from 'pg';
import { Sequelize, type Transaction } from 'sequelize';
import { initModels, type Models } from './models.ts';

// Parse int8 (BIGINT, OID 20) and numeric (OID 1700) as JS Numbers
pg.types.setTypeParser(20, (val: string) => Number(val));
pg.types.setTypeParser(1700, (val: string) => Number(val));

export function toPgSql(sql: string): string {
  let converted = sql;
  const insertOrIgnore = /^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/i;
  const match = converted.match(insertOrIgnore);
  if (match) {
    const [, table, cols, vals] = match;
    converted = `INSERT INTO ${ table }(${ cols }) VALUES(${ vals }) ON CONFLICT DO NOTHING`;
  }
  return converted;
}

export class Database {
  readonly sequelize: Sequelize;
  readonly models: Models;
  private readonly txStorage = new AsyncLocalStorage<Transaction>();
  private initialized = false;

  constructor(connectionString: string) {
    this.sequelize = new Sequelize(connectionString, {
      dialect: 'postgres',
      logging: false,
      pool: {
        max: 20,
        min: 0,
        acquire: 30000,
        idle: 10000,
      },
    });

    this.models = initModels(this.sequelize);
  }

  async init(): Promise<void> {
    if (this.initialized) return;
    await this.sequelize.authenticate();
    await this.sequelize.sync();
    this.initialized = true;
  }

  async ping(): Promise<boolean> {
    try {
      await this.sequelize.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async get<T>(sql: string, ...params: any[]): Promise<T | undefined> {
    const pgSql = toPgSql(sql);
    const tx = this.txStorage.getStore();
    const [results] = await this.sequelize.query(pgSql, {
      replacements: params,
      transaction: tx,
    });
    return (results as T[])[0];
  }

  async all<T>(sql: string, ...params: any[]): Promise<T[]> {
    const pgSql = toPgSql(sql);
    const tx = this.txStorage.getStore();
    const [results] = await this.sequelize.query(pgSql, {
      replacements: params,
      transaction: tx,
    });
    return results as T[];
  }

  async run(sql: string, ...params: any[]): Promise < { changes: number; lastInsertRowid?: number } > {
      const pgSql = toPgSql(sql);
      const tx = this.txStorage.getStore();
      const [, meta] = await this.sequelize.query(pgSql, {
        replacements: params,
        transaction: tx,
      });
      return {
        changes: Number((meta as any)?.rowCount ?? 0),
      };
    }

  /** Runs fn inside an atomic transaction. Nested calls create savepoints. */
  async transaction<T>(fn: () => Promise<T>): Promise < T > {
          const activeTx = this.txStorage.getStore();
          if(activeTx) {
            return await this.sequelize.transaction({ transaction: activeTx }, async (subTx) => {
              return await this.txStorage.run(subTx, fn);
            });
          }

          return await this.sequelize.transaction(async (t) => {
            return await this.txStorage.run(t, fn);
          });
        }

  /** Truncates all tables for testing. */
  async truncateAll(): Promise < void> {
            await this.sequelize.query(`
      TRUNCATE accounts, otps, sessions, challenges, wallets, notes, payments,
               ledger_entries, fraud_events, blocked_wallets, mock_bank_accounts,
               mock_bank_transactions CASCADE;
    `);
          }

  async close(): Promise < void> {
              await this.sequelize.close();
            }
          }
