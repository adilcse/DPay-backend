import type { Config } from '../config.ts';
import { maskPhone, type Logger } from '../lib/logger.ts';

export interface SmsSender {
  sendOtp(phone: string, code: string): Promise<void>;
}

/** Development: logs that an OTP was sent (never the code). Use EXPOSE_DEBUG_OTP to see codes. */
export class ConsoleSmsSender implements SmsSender {
  private readonly logger: Logger;
  constructor(logger: Logger) {
    this.logger = logger;
  }
  async sendOtp(phone: string, code: string): Promise<void> {
    this.logger.info('otp sent (console provider)', { phone: maskPhone(phone), code });
  }
}

/** POSTs `{ phone, message }` to an SMS gateway webhook. */
export class WebhookSmsSender implements SmsSender {
  private readonly url: string;
  private readonly token: string | undefined;
  constructor(url: string, token: string | undefined) {
    this.url = url;
    this.token = token;
  }
  async sendOtp(phone: string, code: string): Promise<void> {
    const res = await fetch(this.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
      },
      body: JSON.stringify({ phone: `+91${phone}`, message: `${code} is your DPay verification code. Don't share it with anyone.` }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`SMS gateway responded HTTP ${res.status}`);
  }
}

export function createSmsSender(config: Config, logger: Logger): SmsSender {
  return config.sms.provider === 'webhook'
    ? new WebhookSmsSender(config.sms.webhookUrl!, config.sms.webhookToken)
    : new ConsoleSmsSender(logger);
}
