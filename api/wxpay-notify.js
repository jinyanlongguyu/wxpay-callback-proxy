/**
 * Vercel Serverless Function — 微信支付回调代理
 * 部署在境外（vercel.app），无需 ICP 备案
 * 收到微信支付回调 → 验签解密 → 转发到本地后端 /internal-notify
 */

const { createDecipheriv } = require('crypto');

// 从 Vercel 环境变量读取（在 Vercel 控制台设置）
//   WX_APIV3_KEY  — 商户平台「APIv3密钥」
//   BACKEND_NOTIFY_URL — 后端 /internal-notify 的公网地址
const WX_APIV3_KEY = process.env.WX_APIV3_KEY || '';
const BACKEND_URL =
  process.env.BACKEND_NOTIFY_URL ||
  'https://c7d96915b60e8c.lhr.life/api/wxpay/internal-notify';

/** AES-256-GCM 解密微信支付回调报文 */
function decryptNotify(ciphertextB64, associatedData, nonce) {
  const key = Buffer.from(WX_APIV3_KEY, 'utf8');
  const iv = Buffer.from(nonce, 'utf8');
  const cipherBuf = Buffer.from(ciphertextB64, 'base64');

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(cipherBuf.slice(-16));
  decipher.setAAD(Buffer.from(associatedData, 'utf8'));

  // cipherBuf 去掉最后 16 字节（auth tag）
  const encrypted = cipherBuf.slice(0, -16);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString('utf8'));
}

/** 将解密后的支付结果转发到本地后端 */
async function forwardToBackend(payload) {
  try {
    const resp = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Wxpay-Callback': '1',
      },
      body: JSON.stringify(payload),
    });
    return resp.ok;
  } catch (e) {
    console.error('[回调代理] 转发失败:', e.message);
    return false;
  }
}

/** Vercel Serverless Function 入口 */
module.exports = async function handler(req, res) {
  // 仅接受 POST
  if (req.method !== 'POST') {
    return res.status(405).json({ code: 'FAIL', message: 'Method Not Allowed' });
  }

  try {
    const { id, event_type, resource } = req.body;
    console.log('[回调代理] 收到通知:', id, event_type);

    // 微信在 headers 中传递签名，这里做基础校验
    const signature = req.headers['wechatpay-signature'];
    const timestamp = req.headers['wechatpay-timestamp'];
    const nonce = req.headers['wechatpay-nonce'];
    const serial = req.headers['wechatpay-serial'];

    if (!signature) {
      console.warn('[回调代理] 缺少微信签名头部，直接返回 SUCCESS');
      return res.status(200).json({ code: 'SUCCESS' });
    }

    // --- 验签（简化版，仅校验 serial 与本地证书匹配）---
    if (serial !== process.env.WX_SERIAL_NO) {
      console.warn('[回调代理] 证书序列号不匹配:', serial);
      // 仍然返回 200，避免微信重推
      return res.status(200).json({ code: 'SUCCESS' });
    }

    // --- 解密 resource ---
    if (!resource || !resource.ciphertext) {
      console.warn('[回调代理] 非支付通知，直接返回 SUCCESS');
      return res.status(200).json({ code: 'SUCCESS' });
    }

    const decrypted = decryptNotify(
      resource.ciphertext,
      resource.associated_data,
      resource.nonce
    );

    console.log('[回调代理] 解密成功:', decrypted.out_trade_no, decrypted.trade_state);

    // --- 转发到后端 ---
    const ok = await forwardToBackend({
      out_trade_no: decrypted.out_trade_no,
      transaction_id: decrypted.transaction_id,
      trade_state: decrypted.trade_state,
      trade_state_desc: decrypted.trade_state_desc || '',
    });

    console.log('[回调代理] 转发结果:', ok ? '✅ 成功' : '❌ 失败');
  } catch (err) {
    console.error('[回调代理] 异常:', err.message, err.stack);
  }

  // 必须返回 200 + SUCCESS，否则微信会重试
  return res.status(200).json({ code: 'SUCCESS' });
};
