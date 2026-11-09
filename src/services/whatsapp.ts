import type { Logger } from '../lib/logger.ts';

export interface WhatsAppConfig {
  accessToken?: string;
  phoneNumberId?: string;
  businessAccountId?: string;
  apiVersion?: string;
  otpTemplate?: string;
  timeoutMs?: number;
}

export interface SendMessageOptions {
  to: string;
  message: string;
  type?: 'text' | string;
}

export interface TemplateBodyParams {
  [key: string]: string | number;
}

export interface TemplateButtonParam {
  type?: string;
  text?: string;
  [key: string]: unknown;
}

export interface TemplateButton {
  type?: string;
  sub_type?: string;
  index?: string | number;
  parameters?: TemplateButtonParam[];
}

export interface SendTemplateParams {
  bodyParams?: TemplateBodyParams | (string | number)[];
  buttonParams?: TemplateButton[];
}

export interface SendTemplateOptions {
  to: string;
  template: string;
  templateParams?: SendTemplateParams;
  languageCode?: string;
}

export interface SendOtpOptions {
  languageCode?: string;
  buttonParams?: TemplateButton[];
  buttonUrl?: string;
}

export interface WhatsAppResponse {
  success: boolean;
  messageId?: string;
  error?: string;
}

/**
 * WhatsApp Business API service for sending messages.
 * Similar to okneppo utils/whatsapp.js, supporting text, templates, and OTPs.
 */
export class WhatsAppService {
  private readonly accessToken: string;
  private readonly phoneNumberId: string;
  private readonly businessAccountId: string;
  private readonly apiVersion: string;
  private readonly defaultOtpTemplate: string;
  private readonly timeoutMs: number;
  private readonly logger?: Logger;

  constructor(config?: WhatsAppConfig, logger?: Logger) {
    this.accessToken = config?.accessToken ?? process.env.WHATSAPP_ACCESS_TOKEN ?? '';
    this.phoneNumberId = config?.phoneNumberId ?? process.env.WHATSAPP_PHONE_NUMBER_ID ?? '';
    this.businessAccountId = config?.businessAccountId ?? process.env.WHATSAPP_BUSINESS_ACCOUNT_ID ?? '';
    this.apiVersion = config?.apiVersion ?? process.env.WHATSAPP_API_VERSION ?? 'v22.0';
    this.defaultOtpTemplate = config?.otpTemplate ?? process.env.WHATSAPP_OTP_TEMPLATE ?? 'app_otp';
    this.timeoutMs = config?.timeoutMs ?? (parseInt(process.env.WHATSAPP_REQUEST_TIMEOUT_MS ?? '', 10) || 10000);
    this.logger = logger;
  }

  get configured(): boolean {
    return Boolean(this.accessToken && this.phoneNumberId);
  }

  /**
   * Format phone number to WhatsApp format (digits only, prepending India 91 if 10 digits).
   */
  formatPhoneNumber(phone: string): string {
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.length > 10) {
      return cleaned;
    }
    if (cleaned.length === 10) {
      return `91${cleaned}`;
    }
    return cleaned;
  }

  /**
   * Send a text message via WhatsApp Business API.
   */
  async sendMessage({ to, message, type = 'text' }: SendMessageOptions): Promise<WhatsAppResponse> {
    try {
      if (!this.accessToken || !this.phoneNumberId) {
        this.log('error', 'WhatsApp API credentials not configured');
        return { success: false, error: 'WhatsApp API credentials not configured' };
      }

      const formattedPhone = this.formatPhoneNumber(to);
      const url = `https://graph.facebook.com/${this.apiVersion}/${this.phoneNumberId}/messages`;

      const payload = {
        messaging_product: 'whatsapp',
        to: formattedPhone,
        type,
        ...(type === 'text' ? { text: { body: message } } : {}),
      };

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      const data = (await response.json()) as any;
      if (!response.ok) {
        this.log('error', 'WhatsApp API error:', data);
        return {
          success: false,
          error: data.error?.message || 'Failed to send WhatsApp message',
        };
      }

      const messageId = data.messages?.[0]?.id;
      if (messageId) {
        this.log('info', 'WhatsApp message sent successfully:', messageId);
      }
      return { success: true, messageId };
    } catch (error) {
      this.log('error', 'Error sending WhatsApp message:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }

  /**
   * Send a template message via WhatsApp Business API with dynamic parameters.
   */
  async sendTemplateMessage({
    to,
    template,
    templateParams,
    languageCode = 'en',
  }: SendTemplateOptions): Promise<WhatsAppResponse> {
    try {
      if (!this.accessToken || !this.phoneNumberId) {
        this.log('error', 'WhatsApp API credentials not configured');
        return { success: false, error: 'WhatsApp API credentials not configured' };
      }

      const formattedPhone = this.formatPhoneNumber(to);
      const url = `https://graph.facebook.com/${this.apiVersion}/${this.phoneNumberId}/messages`;

      const components: any[] = [];

      // Add body parameters if provided
      if (templateParams?.bodyParams && Object.keys(templateParams.bodyParams).length > 0) {
        const bodyParams: any[] = [];
        let paramValues: (string | number | undefined)[];

        if (Array.isArray(templateParams.bodyParams)) {
          paramValues = templateParams.bodyParams;
        } else {
          const keys = Object.keys(templateParams.bodyParams).sort((a, b) => {
            const numA = parseInt(a, 10);
            const numB = parseInt(b, 10);
            if (!isNaN(numA) && !isNaN(numB)) {
              return numA - numB;
            }
            return a.localeCompare(b);
          });
          paramValues = keys.map((key) => (templateParams.bodyParams as TemplateBodyParams)[key]);
        }

        paramValues.forEach((value) => {
          if (value !== null && value !== undefined) {
            const sanitizedText = String(value).replace(/\s+/g, ' ').trim();
            bodyParams.push({
              type: 'text',
              text: sanitizedText,
            });
          }
        });

        if (bodyParams.length > 0) {
          components.push({
            type: 'body',
            parameters: bodyParams,
          });
        }
      }

      // Add button parameters if provided
      if (templateParams?.buttonParams && templateParams.buttonParams.length > 0) {
        templateParams.buttonParams.forEach((button) => {
          const sanitizedParameters = (button.parameters || []).map((param) => {
            if (param.type === 'text' && param.text !== undefined && param.text !== null) {
              return {
                ...param,
                text: String(param.text).replace(/\s+/g, ' ').trim(),
              };
            }
            return param;
          });

          components.push({
            type: 'button',
            sub_type: button.sub_type || 'url',
            index: String(button.index ?? 0),
            parameters: sanitizedParameters,
          });
        });
      }

      const payload: any = {
        messaging_product: 'whatsapp',
        to: formattedPhone,
        type: 'template',
        template: {
          name: template,
          language: { code: languageCode },
        },
      };

      if (components.length > 0) {
        payload.template.components = components;
      }

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      const data = (await response.json()) as any;
      if (!response.ok) {
        this.log('error', 'WhatsApp API error:', data);
        return {
          success: false,
          error: data.error?.message || 'Failed to send WhatsApp template message',
        };
      }

      const messageId = data.messages?.[0]?.id;
      if (messageId) {
        this.log('info', 'WhatsApp template message sent successfully:', messageId);
      }
      return { success: true, messageId };
    } catch (error) {
      this.log('error', 'Error sending WhatsApp template message:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }

  /**
   * Send OTP via WhatsApp template (default template: 'app_otp').
   */
  async sendOTP(
    phone: string,
    otp: string,
    templateName: string = this.defaultOtpTemplate,
    options: SendOtpOptions = {},
  ): Promise<WhatsAppResponse> {
    try {
      const templateParams: SendTemplateParams = {
        bodyParams: {
          '1': otp,
        },
        buttonParams: options.buttonParams ?? [
          {
            sub_type: 'url',
            index: '0',
            parameters: [
              {
                type: 'text',
                text: otp,
              },
            ],
          },
        ],
      };

      return await this.sendTemplateMessage({
        to: phone,
        template: templateName,
        templateParams,
        languageCode: options.languageCode || 'en',
      });
    } catch (error) {
      this.log('error', 'Error sending OTP via WhatsApp:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }

  /**
   * Test template pre-approved by Meta.
   */
  async sendHelloWorldTemplate(phone: string): Promise<WhatsAppResponse> {
    return this.sendTemplateMessage({
      to: phone,
      template: 'hello_world',
      templateParams: {},
      languageCode: 'en',
    });
  }

  private log(level: 'info' | 'warn' | 'error', message: string, ...args: unknown[]) {
    if (this.logger) {
      this.logger[level](message, { meta: args });
    } else {
      if (level === 'error') console.error(message, ...args);
      else if (level === 'warn') console.warn(message, ...args);
      else console.log(message, ...args);
    }
  }
}

export const whatsappService = new WhatsAppService();
