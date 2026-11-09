import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createLogger } from '../src/lib/logger.ts';
import { ConsoleSmsSender, createSmsSender, WebhookSmsSender, WhatsAppSmsSender } from '../src/services/sms.ts';
import { WhatsAppService } from '../src/services/whatsapp.ts';

describe('WhatsAppService & WhatsApp OTP sender', () => {
  const logger = createLogger('silent');

  it('formats phone numbers correctly for WhatsApp', () => {
    const ws = new WhatsAppService();
    // 10-digit Indian phone number: prepend 91
    assert.equal(ws.formatPhoneNumber('9876543210'), '919876543210');
    // Number with +91 or formatting
    assert.equal(ws.formatPhoneNumber('+91 98765 43210'), '919876543210');
    // Already has 91 prefix and 12 digits
    assert.equal(ws.formatPhoneNumber('919876543210'), '919876543210');
    // Number with hyphens
    assert.equal(ws.formatPhoneNumber('+91-98765-43210'), '919876543210');
  });

  it('returns an error if credentials are not configured', async () => {
    const ws = new WhatsAppService({ accessToken: '', phoneNumberId: '' });
    assert.equal(ws.configured, false);

    const msgRes = await ws.sendMessage({ to: '9876543210', message: 'test' });
    assert.equal(msgRes.success, false);
    assert.match(msgRes.error!, /credentials not configured/i);

    const otpRes = await ws.sendOTP('9876543210', '123456');
    assert.equal(otpRes.success, false);
    assert.match(otpRes.error!, /credentials not configured/i);
  });

  it('sends OTP with correct payload and headers when mocked', async () => {
    const originalFetch = globalThis.fetch;
    let interceptedUrl = '';
    let interceptedHeaders: Record<string, string> = {};
    let interceptedBody: any = null;

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      interceptedUrl = String(url);
      interceptedHeaders = (init?.headers as Record<string, string>) || {};
      interceptedBody = JSON.parse(String(init?.body || '{}'));
      return new Response(JSON.stringify({ messages: [{ id: 'wamid.test.123' }] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as any;

    try {
      const ws = new WhatsAppService({
        accessToken: 'mock_token',
        phoneNumberId: 'mock_phone_id',
        apiVersion: 'v22.0',
        otpTemplate: 'app_otp',
      });

      const res = await ws.sendOTP('9876543210', '654321');
      assert.equal(res.success, true);
      assert.equal(res.messageId, 'wamid.test.123');

      assert.equal(interceptedUrl, 'https://graph.facebook.com/v22.0/mock_phone_id/messages');
      assert.equal(interceptedHeaders['Authorization'], 'Bearer mock_token');
      assert.equal(interceptedHeaders['Content-Type'], 'application/json');

      assert.equal(interceptedBody.messaging_product, 'whatsapp');
      assert.equal(interceptedBody.to, '919876543210');
      assert.equal(interceptedBody.type, 'template');
      assert.equal(interceptedBody.template.name, 'app_otp');
      assert.equal(interceptedBody.template.language.code, 'en');

      // Body parameter
      assert.deepEqual(interceptedBody.template.components[0], {
        type: 'body',
        parameters: [{ type: 'text', text: '654321' }],
      });

      // Button parameter
      assert.deepEqual(interceptedBody.template.components[1], {
        type: 'button',
        sub_type: 'url',
        index: '0',
        parameters: [{ type: 'text', text: '654321' }],
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('WhatsAppSmsSender throws if WhatsApp API fails', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({ error: { message: 'Invalid OAuth access token' } }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as any;

    try {
      const ws = new WhatsAppService({
        accessToken: 'bad_token',
        phoneNumberId: 'mock_phone_id',
      });
      const sender = new WhatsAppSmsSender(ws, logger, 'app_otp');

      await assert.rejects(
        async () => {
          await sender.sendOtp('9876543210', '123456');
        },
        {
          name: 'Error',
          message: 'Invalid OAuth access token',
        },
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('createSmsSender creates appropriate sender based on provider config', () => {
    const consoleSender = createSmsSender(
      {
        sms: { provider: 'console', webhookUrl: undefined, webhookToken: undefined },
      } as any,
      logger,
    );
    assert.ok(consoleSender instanceof ConsoleSmsSender);

    const webhookSender = createSmsSender(
      {
        sms: { provider: 'webhook', webhookUrl: 'https://example.com/sms', webhookToken: 'secret' },
      } as any,
      logger,
    );
    assert.ok(webhookSender instanceof WebhookSmsSender);

    const whatsappSender = createSmsSender(
      {
        sms: {
          provider: 'whatsapp',
          webhookUrl: undefined,
          webhookToken: undefined,
          whatsapp: {
            accessToken: 'token',
            phoneNumberId: 'phone_id',
            apiVersion: 'v22.0',
            otpTemplate: 'app_otp',
            timeoutMs: 10000,
          },
        },
      } as any,
      logger,
    );
    assert.ok(whatsappSender instanceof WhatsAppSmsSender);
  });
});
