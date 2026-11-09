import type { Config } from '../config.ts';
import { maskPhone, type Logger } from '../lib/logger.ts';
import { WhatsAppService } from './whatsapp.ts';

export interface SmsSender {
  sendOtp(phone: string, code: string): Promise<void>;
}

/** Development: logs that an OTP was sent (never the code). Use EXPOSE_DEBUG_OTP to see codes. */
export class ConsoleSmsSender implements SmsSender {
  private readonly logger: Logger;
  constructor(logger: Logger) {
    this.logger = logger;
  }
  async sendOtp(phone: string, _code: string): Promise<void> {
    this.logger.info('otp sent (console provider)', { phone: maskPhone(phone) });
  }
}

/** Sends OTP via WhatsApp Cloud API template message. */
export class WhatsAppSmsSender implements SmsSender {
  private readonly whatsapp: WhatsAppService;
  private readonly logger: Logger;
  private readonly templateName: string;

  constructor(whatsapp: WhatsAppService, logger: Logger, templateName: string = 'app_otp') {
    this.whatsapp = whatsapp;
    this.logger = logger;
    this.templateName = templateName;
  }

  async sendOtp(phone: string, code: string): Promise<void> {
    const res = await this.whatsapp.sendOTP(phone, code, this.templateName);
    if (!res.success) {
      this.logger.error('failed to send whatsapp otp', { phone: maskPhone(phone), error: res.error });
      throw new Error(res.error || 'WhatsApp OTP delivery failed');
    }
    this.logger.info('otp sent (whatsapp provider)', {
      phone: maskPhone(phone),
      messageId: res.messageId,
    });
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
  if (config.sms.provider === 'whatsapp') {
    const service = new WhatsAppService(config.sms.whatsapp, logger);
    return new WhatsAppSmsSender(service, logger, config.sms.whatsapp?.otpTemplate);
  }
  return config.sms.provider === 'webhook'
    ? new WebhookSmsSender(config.sms.webhookUrl!, config.sms.webhookToken)
    : new ConsoleSmsSender(logger);
}
