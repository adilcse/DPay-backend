import { DataTypes, Model, type Sequelize } from 'sequelize';

export class AccountModel extends Model {}
export class OtpModel extends Model {}
export class SessionModel extends Model {}
export class ChallengeModel extends Model {}
export class WalletModel extends Model {}
export class NoteModel extends Model {}
export class PaymentModel extends Model {}
export class LedgerEntryModel extends Model {}
export class FraudEventModel extends Model {}
export class BlockedWalletModel extends Model {}
export class MockBankAccountModel extends Model {}
export class MockBankTransactionModel extends Model {}

export function initModels(sequelize: Sequelize) {
  AccountModel.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true },
      phone: { type: DataTypes.STRING, allowNull: false, unique: true },
      full_name: { type: DataTypes.STRING, allowNull: false },
      handle: { type: DataTypes.STRING, allowNull: false, unique: true },
      email: { type: DataTypes.STRING, allowNull: true },
      online_balance_paise: { type: DataTypes.BIGINT, allowNull: false, defaultValue: 0 },
      bound_device_id: { type: DataTypes.STRING, allowNull: true },
      frozen: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      created_at: { type: DataTypes.BIGINT, allowNull: false },
      updated_at: { type: DataTypes.BIGINT, allowNull: false },
    },
    { sequelize, tableName: 'accounts', timestamps: false, underscored: true },
  );

  OtpModel.init(
    {
      phone: { type: DataTypes.STRING, primaryKey: true },
      code_hash: { type: DataTypes.STRING, allowNull: false },
      expires_at: { type: DataTypes.BIGINT, allowNull: false },
      resend_at: { type: DataTypes.BIGINT, allowNull: false },
      attempts: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      window_start: { type: DataTypes.BIGINT, allowNull: false },
      sends_in_window: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
    },
    { sequelize, tableName: 'otps', timestamps: false, underscored: true },
  );

  SessionModel.init(
    {
      token_hash: { type: DataTypes.STRING, primaryKey: true },
      phone: { type: DataTypes.STRING, allowNull: false },
      device_id: { type: DataTypes.STRING, allowNull: false },
      created_at: { type: DataTypes.BIGINT, allowNull: false },
      expires_at: { type: DataTypes.BIGINT, allowNull: false },
      last_seen_at: { type: DataTypes.BIGINT, allowNull: false },
    },
    { sequelize, tableName: 'sessions', timestamps: false, underscored: true },
  );

  ChallengeModel.init(
    {
      challenge: { type: DataTypes.STRING, primaryKey: true },
      account_id: { type: DataTypes.STRING, allowNull: false },
      expires_at: { type: DataTypes.BIGINT, allowNull: false },
    },
    { sequelize, tableName: 'challenges', timestamps: false, underscored: true },
  );

  WalletModel.init(
    {
      wallet_id: { type: DataTypes.STRING, primaryKey: true },
      account_id: { type: DataTypes.STRING, allowNull: false },
      wallet_key: { type: DataTypes.STRING, allowNull: false, unique: true },
      certificate: { type: DataTypes.BLOB, allowNull: false },
      cert_not_after: { type: DataTypes.BIGINT, allowNull: false },
      device_id: { type: DataTypes.STRING, allowNull: false },
      status: { type: DataTypes.STRING, allowNull: false },
      frozen: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      security_level: { type: DataTypes.STRING, allowNull: false },
      integrity_tier: { type: DataTypes.STRING, allowNull: false },
      offline_limit_paise: { type: DataTypes.BIGINT, allowNull: false },
      lease_sequence: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      lease_issued_at: { type: DataTypes.BIGINT, allowNull: true },
      lease_not_after: { type: DataTypes.BIGINT, allowNull: true },
      created_at: { type: DataTypes.BIGINT, allowNull: false },
      retired_at: { type: DataTypes.BIGINT, allowNull: true },
    },
    { sequelize, tableName: 'wallets', timestamps: false, underscored: true },
  );

  NoteModel.init(
    {
      note_id: { type: DataTypes.STRING, primaryKey: true },
      wallet_id: { type: DataTypes.STRING, allowNull: false },
      account_id: { type: DataTypes.STRING, allowNull: false },
      value_paise: { type: DataTypes.BIGINT, allowNull: false },
      note_key: { type: DataTypes.STRING, allowNull: false, unique: true },
      not_after: { type: DataTypes.BIGINT, allowNull: false },
      status: { type: DataTypes.STRING, allowNull: false },
      usage_limit_hardware: { type: DataTypes.INTEGER, allowNull: false },
      payment_id: { type: DataTypes.STRING, allowNull: true },
      issued_at: { type: DataTypes.BIGINT, allowNull: false },
      closed_at: { type: DataTypes.BIGINT, allowNull: true },
    },
    { sequelize, tableName: 'notes', timestamps: false, underscored: true },
  );

  PaymentModel.init(
    {
      payment_id: { type: DataTypes.STRING, primaryKey: true },
      body_hash: { type: DataTypes.STRING, allowNull: false },
      payer_wallet_id: { type: DataTypes.STRING, allowNull: false },
      receiver_wallet_id: { type: DataTypes.STRING, allowNull: false },
      payer_account_id: { type: DataTypes.STRING, allowNull: false },
      receiver_account_id: { type: DataTypes.STRING, allowNull: false },
      amount_paise: { type: DataTypes.BIGINT, allowNull: false },
      total_note_value_paise: { type: DataTypes.BIGINT, allowNull: false },
      change_paise: { type: DataTypes.BIGINT, allowNull: false },
      note_count: { type: DataTypes.INTEGER, allowNull: false },
      created_at_claimed: { type: DataTypes.BIGINT, allowNull: false },
      received_at: { type: DataTypes.BIGINT, allowNull: true },
      settled_at: { type: DataTypes.BIGINT, allowNull: false },
      uploaded_by: { type: DataTypes.STRING, allowNull: false },
      double_spend_guaranteed: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    },
    { sequelize, tableName: 'payments', timestamps: false, underscored: true },
  );

  LedgerEntryModel.init(
    {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
      account_id: { type: DataTypes.STRING, allowNull: false },
      kind: { type: DataTypes.STRING, allowNull: false },
      amount_paise: { type: DataTypes.BIGINT, allowNull: false },
      balance_after_paise: { type: DataTypes.BIGINT, allowNull: false },
      reference: { type: DataTypes.STRING, allowNull: true },
      created_at: { type: DataTypes.BIGINT, allowNull: false },
    },
    { sequelize, tableName: 'ledger_entries', timestamps: false, underscored: true },
  );

  FraudEventModel.init(
    {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
      kind: { type: DataTypes.STRING, allowNull: false },
      wallet_id: { type: DataTypes.STRING, allowNull: true },
      note_id: { type: DataTypes.STRING, allowNull: true },
      first_payment_id: { type: DataTypes.STRING, allowNull: true },
      second_payment_id: { type: DataTypes.STRING, allowNull: true },
      detail: { type: DataTypes.STRING, allowNull: true },
      created_at: { type: DataTypes.BIGINT, allowNull: false },
    },
    { sequelize, tableName: 'fraud_events', timestamps: false, underscored: true },
  );

  BlockedWalletModel.init(
    {
      wallet_id: { type: DataTypes.STRING, primaryKey: true },
      reason: { type: DataTypes.STRING, allowNull: false },
      created_at: { type: DataTypes.BIGINT, allowNull: false },
    },
    { sequelize, tableName: 'blocked_wallets', timestamps: false, underscored: true },
  );

  MockBankAccountModel.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true },
      account_id: { type: DataTypes.STRING, allowNull: false },
      account_number: { type: DataTypes.STRING, allowNull: false, unique: true },
      ifsc: { type: DataTypes.STRING, allowNull: false },
      bank_name: { type: DataTypes.STRING, allowNull: false },
      upi_vpa: { type: DataTypes.STRING, allowNull: false },
      infinite_money: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
      balance_paise: { type: DataTypes.BIGINT, allowNull: false, defaultValue: 100000000000 },
      status: { type: DataTypes.STRING, allowNull: false, defaultValue: 'ACTIVE' },
      created_at: { type: DataTypes.BIGINT, allowNull: false },
      updated_at: { type: DataTypes.BIGINT, allowNull: false },
    },
    { sequelize, tableName: 'mock_bank_accounts', timestamps: false, underscored: true },
  );

  MockBankTransactionModel.init(
    {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
      account_id: { type: DataTypes.STRING, allowNull: false },
      bank_account_id: { type: DataTypes.STRING, allowNull: false },
      type: { type: DataTypes.STRING, allowNull: false },
      amount_paise: { type: DataTypes.BIGINT, allowNull: false },
      status: { type: DataTypes.STRING, allowNull: false },
      reference: { type: DataTypes.STRING, allowNull: false },
      description: { type: DataTypes.STRING, allowNull: true },
      created_at: { type: DataTypes.BIGINT, allowNull: false },
    },
    { sequelize, tableName: 'mock_bank_transactions', timestamps: false, underscored: true },
  );

  return {
    Account: AccountModel,
    Otp: OtpModel,
    Session: SessionModel,
    Challenge: ChallengeModel,
    Wallet: WalletModel,
    Note: NoteModel,
    Payment: PaymentModel,
    LedgerEntry: LedgerEntryModel,
    FraudEvent: FraudEventModel,
    BlockedWallet: BlockedWalletModel,
    MockBankAccount: MockBankAccountModel,
    MockBankTransaction: MockBankTransactionModel,
  };
}

export type Models = ReturnType<typeof initModels>;

