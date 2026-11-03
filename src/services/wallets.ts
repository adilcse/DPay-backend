import { AttestationError, type AttestationResult } from '../attestation/verifier.ts';
import { integrityRequestHash, type IntegrityTier } from '../attestation/playIntegrity.ts';
import { BankError, BankException } from '../domain/errors.ts';
import { Limits } from '../domain/limits.ts';
import { isValidDenominationPlan, planDenominations } from '../protocol/denominations.ts';
import { ProtocolConstants } from '../protocol/messages.ts';
import * as P256 from '../protocol/p256.ts';
import { requireAccount, type AccountRow } from './accounts.ts';
import type { Session } from './auth.ts';
import { hex, unhex, type ServiceContext } from './context.ts';
import { LedgerKind, postLedger } from './ledger.ts';
import { autoFundShortfall } from './mockBank.ts';

export interface KeyAttestationRequest {
  /** Compressed P-256 public key (33 bytes). */
  readonly publicKey: Buffer;
  /** DER certificates, leaf first. */
  readonly attestationChain: readonly Buffer[];
}

export interface WalletRow {
  wallet_id: string;
  account_id: string;
  wallet_key: string;
  certificate: Uint8Array;
  cert_not_after: number;
  device_id: string;
  status: 'ACTIVE' | 'RETIRED';
  frozen: number;
  security_level: string;
  integrity_tier: string;
  offline_limit_paise: number;
  lease_sequence: number;
  lease_issued_at: number | null;
  lease_not_after: number | null;
  created_at: number;
  retired_at: number | null;
}

export interface NoteRow {
  note_id: string;
  wallet_id: string;
  account_id: string;
  value_paise: number;
  note_key: string;
  not_after: number;
  status: 'OUTSTANDING' | 'SPENT' | 'REFUNDED';
  usage_limit_hardware: number;
  payment_id: string | null;
  issued_at: number;
  closed_at: number | null;
}

export interface LeaseRefresh {
  lease: Buffer;
  outstandingNoteIds: Buffer[];
  sequence: number;
  issuedAt: number;
  notAfter: number;
  outstandingValuePaise: number;
}

// --- Guards ------------------------------------------------------------------------------------

function requireBoundDevice(account: AccountRow, session: Session): void {
  if (account.frozen) throw new BankException(BankError.WALLET_FROZEN);
  if (account.bound_device_id !== null && account.bound_device_id !== session.deviceId) {
    throw new BankException(BankError.DEVICE_MOVED, 'the account is bound to another device');
  }
}

  export async function activeWallet(ctx: ServiceContext, accountId: string): Promise<WalletRow | undefined> {
    return await ctx.db.get<WalletRow>(`SELECT * FROM wallets WHERE account_id = ? AND status = 'ACTIVE'`, accountId);
  }

  /** The session's account, its device binding and its active wallet: required to load, lease or spend. */
    async function requireActiveWallet(ctx: ServiceContext, session: Session): Promise<{ account: AccountRow; wallet: WalletRow }> {
      const account = await requireAccount(ctx, session);
      requireBoundDevice(account, session);
      const wallet = await activeWallet(ctx, account.id);
      if (!wallet) throw new BankException(BankError.WALLET_NOT_PROVISIONED);
      if (wallet.device_id !== session.deviceId) throw new BankException(BankError.DEVICE_MOVED);
      if (wallet.frozen) throw new BankException(BankError.WALLET_FROZEN);
      return { account, wallet };
    }

    // --- Challenges ----------------------------------------------------------------------------------

    /** Fresh single-use attestation challenge for key generation. */
      export async function provisioningChallenge(ctx: ServiceContext, session: Session): Promise<{ challenge: Buffer; expiresAt: number }> {
        const account = await requireAccount(ctx, session);
        requireBoundDevice(account, session);
        const now = ctx.clock();
        const challenge = ctx.random(ProtocolConstants.CHALLENGE_SIZE);
        const expiresAt = now + Limits.CHALLENGE_TTL_SECONDS;
          const challengeHex = hex(challenge);

          await ctx.db.transaction(async () => {
            await ctx.db.run('DELETE FROM challenges WHERE account_id = ? AND expires_at < ?', account.id, now);
            await ctx.db.run('INSERT INTO challenges (challenge, account_id, expires_at) VALUES (?, ?, ?)', challengeHex, account.id, expiresAt);
          });

          // Fast single-use cache in Redis
          await ctx.redis.setChallenge(challengeHex, account.id, Limits.CHALLENGE_TTL_SECONDS);

          return { challenge, expiresAt };
        }

            async function consumeChallenge(ctx: ServiceContext, accountId: string, challenge: Buffer): Promise<void> {
              const now = ctx.clock();
  const challengeHex = hex(challenge);

              // Consume from Redis if present
              await ctx.redis.consumeChallenge(challengeHex, accountId);

              const { changes } = await ctx.db.run(
                'DELETE FROM challenges WHERE challenge = ? AND account_id = ? AND expires_at >= ?',
                challengeHex,
                accountId,
                now,
              );
              if (changes !== 1) throw new BankException(BankError.INVALID_CHALLENGE);
            }

            function validateKey(publicKey: Buffer): void {
              try {
                P256.decompress(publicKey);
              } catch {
                throw new BankException(BankError.INVALID_REQUEST, 'public key is not a valid compressed P-256 point');
              }
            }

            async function verifyAttestation(
              ctx: ServiceContext,
              key: KeyAttestationRequest,
              challenge: Buffer,
              kind: 'identity' | 'note',
            ): Promise<AttestationResult> {
              try {
                return await ctx.attestation.verify({ publicKey: key.publicKey, chain: key.attestationChain, challenge, kind });
              } catch (e) {
                if (e instanceof AttestationError) {
                  ctx.logger.warn('attestation rejected', { kind, reason: e.message });
                  throw new BankException(BankError.ATTESTATION_FAILED, e.message);
                }
                throw e;
              }
            }

            // --- Wallet certificate --------------------------------------------------------------------------

            /**
             * Verifies the identity key's attestation (and Play Integrity when enabled), binds the account to
             * this device and returns a signed wallet certificate. Re-provisioning (reinstall, wiped data)
             * retires the previous wallet; its notes are refunded once they expire, unless they settle first.
             */
            export async function certifyWallet(
              ctx: ServiceContext,
              session: Session,
              challenge: Buffer,
              identity: KeyAttestationRequest,
              integrityToken: string | undefined,
            ) {
              const account = await requireAccount(ctx, session);
              requireBoundDevice(account, session);
              validateKey(identity.publicKey);
              await ctx.db.transaction(async () => await consumeChallenge(ctx, account.id, challenge));

              const attestation = await verifyAttestation(ctx, identity, challenge, 'identity');
              let integrity: IntegrityTier;
              try {
                integrity = await ctx.integrity.verify(integrityToken, integrityRequestHash(challenge, identity.publicKey));
              } catch (e) {
                if (e instanceof AttestationError) throw new BankException(BankError.ATTESTATION_FAILED, e.message);
                throw e;
              }
              const offlineLimit =
                integrity === 'DEVICE' ? Math.min(Limits.MAX_OFFLINE_BALANCE_PAISE, ctx.config.reducedOfflineLimitPaise) : Limits.MAX_OFFLINE_BALANCE_PAISE;

              const now = ctx.clock();
                return await ctx.db.transaction(async () => {
                  const fresh = await requireAccount(ctx, session);
                  requireBoundDevice(fresh, session);
                    if (await ctx.db.get('SELECT 1 AS x FROM wallets WHERE wallet_key = ?', hex(identity.publicKey))) {
                      throw new BankException(BankError.INVALID_REQUEST, 'this identity key is already registered');
                    }
                    await ctx.db.run(`UPDATE wallets SET status = 'RETIRED', retired_at = ? WHERE account_id = ? AND status = 'ACTIVE'`, now, fresh.id);

                    const walletId = ctx.random(ProtocolConstants.ID_SIZE);
                    const notAfter = now + Limits.WALLET_CERT_LIFETIME_SECONDS;
                    const certificate = ctx.issuer.walletCertificate(walletId, identity.publicKey, fresh.handle, notAfter);
                      await ctx.db.run(
                        `INSERT INTO wallets (wallet_id, account_id, wallet_key, certificate, cert_not_after, device_id, status, frozen,
         security_level, integrity_tier, offline_limit_paise, lease_sequence, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 0, ?, ?, ?, 0, ?)`,
                        hex(walletId),
                        fresh.id,
                        hex(identity.publicKey),
                        certificate,
                        notAfter,
                        session.deviceId,
                        attestation.securityLevel,
                        integrity,
                        offlineLimit,
                        now,
                      );
                    await ctx.db.run('UPDATE accounts SET bound_device_id = ?, updated_at = ? WHERE id = ?', session.deviceId, now, fresh.id);
                    ctx.logger.info('wallet certified', { walletId: hex(walletId), securityLevel: attestation.securityLevel, integrity });
                    return {
                      walletCertificate: certificate,
                      walletId,
                      securityLevel: attestation.securityLevel,
                      offlineLimitPaise: offlineLimit,
                    };
                  });
              }

// --- Notes ---------------------------------------------------------------------------------------

                    async function outstandingNotes(ctx: ServiceContext, walletId: string, now: number): Promise<NoteRow[]> {
                      return await ctx.db.all<NoteRow>(
                        `SELECT * FROM notes WHERE wallet_id = ? AND status = 'OUTSTANDING' AND not_after > ? ORDER BY note_id`,
                        walletId,
                        now,
                      );
                    }

/**
 * Deducts the total from the online balance, then signs one note certificate per key, then a fresh
 * lease covering the new notes (PROTOCOL.md "Issuing notes"). [values] must be exactly
 * `DenominationPlanner.plan(total)`, in the same order as [keys].
 */
export async function issueNotes(
                      ctx: ServiceContext,
                      session: Session,
                      challenge: Buffer,
                      values: readonly number[],
                      keys: readonly KeyAttestationRequest[],
                    ) {
                    const { account } = await requireActiveWallet(ctx, session);
                    const total = values.reduce((a, b) => a + b, 0);
                    if (
                      values.length === 0 ||
                      values.length > Limits.MAX_NOTES_PER_LOAD ||
                      values.length !== keys.length ||
                      !isValidDenominationPlan(values, total)
                    ) {
                      throw new BankException(BankError.INVALID_DENOMINATIONS, 'note denominations do not match expected plan');
                    }
                    keys.forEach((k) => validateKey(k.publicKey));
                    if (new Set(keys.map((k) => hex(k.publicKey))).size !== keys.length) {
                      throw new BankException(BankError.INVALID_REQUEST, 'duplicate note key');
                    }
                    await ctx.db.transaction(async () => await consumeChallenge(ctx, account.id, challenge));

                    const attestations: AttestationResult[] = [];
                    for (const key of keys) attestations.push(await verifyAttestation(ctx, key, challenge, 'note'));
                    const allHardwareEnforced = attestations.every((a) => a.usageLimitHardwareEnforced);

                    const now = ctx.clock();
                      return await ctx.db.transaction(async () => {
                        const { account: fresh, wallet } = await requireActiveWallet(ctx, session);
                        await refundExpiredNotes(ctx, now, fresh.id);

                        let limit = wallet.offline_limit_paise;
                        if (!allHardwareEnforced && limit > ctx.config.reducedOfflineLimitPaise) {
                          // Single use only enforced by keystore2 (software): lower this wallet's cap for good.
                          limit = ctx.config.reducedOfflineLimitPaise;
                          await ctx.db.run('UPDATE wallets SET offline_limit_paise = ? WHERE wallet_id = ?', limit, wallet.wallet_id);
                        }
                        const notesOutstanding = await outstandingNotes(ctx, wallet.wallet_id, now);
                        const outstanding = notesOutstanding.reduce((s, n) => s + n.value_paise, 0);
                        if (outstanding + total > limit) {
                          throw new BankException(BankError.LIMIT_EXCEEDED, 'offline limit exceeded', {
                            limitPaise: limit,
                            remainingPaise: Math.max(0, limit - outstanding),
                          });
                        }

                        let balanceRow = await ctx.db.get<{ b: number }>('SELECT online_balance_paise AS b FROM accounts WHERE id = ?', fresh.id);
                        let balance = balanceRow!.b;

                        // If online balance is lower than required, auto-load from mock bank if infinite money is enabled
                        if (balance < total) {
                          if (ctx.config.mockBank.autoLoad && ctx.config.mockBank.infiniteMoney) {
                            await autoFundShortfall(ctx, fresh.id, total, now);
                            balanceRow = await ctx.db.get<{ b: number }>('SELECT online_balance_paise AS b FROM accounts WHERE id = ?', fresh.id);
                            balance = balanceRow!.b;
                          }
                        }

                        if (balance < total) throw new BankException(BankError.INSUFFICIENT_BALANCE);

                        for (const key of keys) {
                            if (await ctx.db.get('SELECT 1 AS x FROM notes WHERE note_key = ?', hex(key.publicKey))) {
                              throw new BankException(BankError.INVALID_REQUEST, 'note key already used');
                            }
                          }

                          // Debit before signing any note certificate.
                          const walletId = unhex(wallet.wallet_id);
                          const notAfter = now + ctx.config.noteLifetimeSeconds;
                          const noteIds = keys.map(() => ctx.random(ProtocolConstants.ID_SIZE));
                            await postLedger(ctx.db, fresh.id, LedgerKind.OFFLINE_LOAD, -total, `load:${hex(noteIds[0]!)}`, now);

                            const noteCertificates: Buffer[] = [];
                            for (let i = 0; i < keys.length; i++) {
                              const key = keys[i]!;
                              const value = values[i]!;
                                await ctx.db.run(
                                  `INSERT INTO notes (note_id, wallet_id, account_id, value_paise, note_key, not_after, status, usage_limit_hardware, issued_at)
         VALUES (?, ?, ?, ?, ?, ?, 'OUTSTANDING', ?, ?)`,
                                  hex(noteIds[i]!),
                                  wallet.wallet_id,
                                  fresh.id,
                                  value,
                                  hex(key.publicKey),
                                  notAfter,
                                  attestations[i]!.usageLimitHardwareEnforced ? 1 : 0,
                                  now,
                                );
                          noteCertificates.push(ctx.issuer.noteCertificate(noteIds[i]!, walletId, value, key.publicKey, notAfter));
                        }

                        const lease = await issueLease(ctx, wallet.wallet_id, now);
                        ctx.logger.info('notes issued', { walletId: wallet.wallet_id, count: keys.length, totalPaise: total });
                        return { noteCertificates, ...lease };
                      });
                    }

// --- Leases --------------------------------------------------------------------------------------

/** Signs the next lease for [walletId]. Must run inside a transaction, after any note changes. */
                        async function issueLease(ctx: ServiceContext, walletId: string, now: number): Promise<LeaseRefresh> {
                          const wallet = (await ctx.db.get<WalletRow>('SELECT * FROM wallets WHERE wallet_id = ?', walletId))!;
                          const notes = await outstandingNotes(ctx, walletId, now);
                          const sequence = wallet.lease_sequence + 1;
                          const notAfter = now + Limits.LEASE_VALIDITY_SECONDS;
                          const outstandingNoteIds = notes.map((n) => unhex(n.note_id));
                          const outstandingValuePaise = notes.reduce((s, n) => s + n.value_paise, 0);
                          const lease = ctx.issuer.lease({
                            walletId: unhex(walletId),
                            walletKey: unhex(wallet.wallet_key),
                            sequence,
                            issuedAt: now,
                            notAfter,
                            outstandingValue: outstandingValuePaise,
                            noteIds: outstandingNoteIds,
                          });
                            await ctx.db.run(
                              'UPDATE wallets SET lease_sequence = ?, lease_issued_at = ?, lease_not_after = ? WHERE wallet_id = ?',
                              sequence,
                              now,
                              notAfter,
                              walletId,
                            );
                          return { lease, outstandingNoteIds, sequence, issuedAt: now, notAfter, outstandingValuePaise };
                        }

                        /** Issues a new 5-day wallet lease plus the outstanding note ids it covers. Refused to frozen or moved wallets. */
                          export async function refreshLease(ctx: ServiceContext, session: Session): Promise<LeaseRefresh> {
                            const now = ctx.clock();
                              return await ctx.db.transaction(async () => {
                                const { account, wallet } = await requireActiveWallet(ctx, session);
                                await refundExpiredNotes(ctx, now, account.id);
                                return await issueLease(ctx, wallet.wallet_id, now);
                              });
                            }

// --- Refunds -------------------------------------------------------------------------------------

/**
 * Refunds notes still outstanding after `notAfter + settlement grace` (expired unspent, LOST to
 * biometric re-enrollment, device loss, or left on a retired wallet). Returns the amount refunded
 * to [accountId] (or to everyone when omitted). Must run inside a transaction.
 */
                              export async function refundExpiredNotes(ctx: ServiceContext, now: number, accountId?: string): Promise<number> {
                                const cutoff = now - ctx.config.settlementGraceSeconds;
                                const notes = accountId
    ?await ctx.db.all<NoteRow>(`SELECT * FROM notes WHERE status = 'OUTSTANDING' AND not_after <= ? AND account_id = ?`, cutoff, accountId)
    : await ctx.db.all<NoteRow>(`SELECT * FROM notes WHERE status = 'OUTSTANDING' AND not_after <= ?`, cutoff);
                                let refunded = 0;
                                for (const note of notes) {
                                  await ctx.db.run(`UPDATE notes SET status = 'REFUNDED', closed_at = ? WHERE note_id = ?`, now, note.note_id);
                                  await postLedger(ctx.db, note.account_id, LedgerKind.NOTE_EXPIRY_REFUND, note.value_paise, `note:${note.note_id}`, now);
                                  refunded += note.value_paise;
                                }
                                return refunded;
                              }

                              // --- Status --------------------------------------------------------------------------------------

                                export async function walletStatus(ctx: ServiceContext, session: Session) {
                                  const account = await requireAccount(ctx, session);
                                  const wallet = await activeWallet(ctx, account.id);
                                  const now = ctx.clock();
                                  if (!wallet) {
                                    return { provisioned: false as const, boundToThisDevice: account.bound_device_id === null || account.bound_device_id === session.deviceId };
                                  }
                                  const notes = await ctx.db.all<NoteRow>(`SELECT * FROM notes WHERE wallet_id = ? ORDER BY issued_at DESC, value_paise DESC`, wallet.wallet_id);
                                  const outstanding = notes.filter((n) => n.status === 'OUTSTANDING' && n.not_after > now).reduce((s, n) => s + n.value_paise, 0);
                                  return {
                                    provisioned: true as const,
                                    boundToThisDevice: wallet.device_id === session.deviceId && account.bound_device_id === session.deviceId,
                                    walletId: unhex(wallet.wallet_id),
                                    displayName: account.handle,
                                    walletCertificate: Buffer.from(wallet.certificate),
                                    certificateNotAfter: wallet.cert_not_after,
                                    securityLevel: wallet.security_level,
                                    integrityTier: wallet.integrity_tier,
                                    frozen: wallet.frozen === 1 || account.frozen === 1,
                                    offlineLimitPaise: wallet.offline_limit_paise,
                                    outstandingValuePaise: outstanding,
                                    remainingLoadCapacityPaise: Math.max(0, wallet.offline_limit_paise - outstanding),
                                    lease:
                                      wallet.lease_sequence > 0
                                        ? { sequence: wallet.lease_sequence, issuedAt: wallet.lease_issued_at!, notAfter: wallet.lease_not_after! }
                                        : null,
                                    notes: notes.map((n) => ({
                                      noteId: unhex(n.note_id),
                                      valuePaise: n.value_paise,
                                      notAfter: n.not_after,
                                      status: n.status === 'OUTSTANDING' && n.not_after <= now ? ('EXPIRED' as const) : n.status,
                                      refundAt: n.status === 'OUTSTANDING' ? n.not_after + ctx.config.settlementGraceSeconds : null,
                                    })),
                                  };
                                }
