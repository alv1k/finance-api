import nodemailer from 'nodemailer'

const SMTP_HOST = process.env.SMTP_HOST || 'smtp-relay.brevo.com'
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10)
const SMTP_USER = process.env.SMTP_USER || ''
const SMTP_PASS = process.env.SMTP_PASSWORD || process.env.SMTP_PASS || ''
const SMTP_SECURE = process.env.SMTP_SECURE === 'true' || SMTP_PORT === 465
const SMTP_FROM = process.env.SMTP_FROM || 'TIIN Finance <noreply@tiinservice.online>'

let transporter = null

function getTransporter() {
  if (transporter) return transporter

  const baseOptions = {
    host: SMTP_HOST,
    port: SMTP_PORT,
    connectionTimeout: 4000,
    greetingTimeout: 4000,
    socketTimeout: 5000,
    tls: {
      rejectUnauthorized: false
    }
  }

  if (SMTP_USER && SMTP_PASS) {
    transporter = nodemailer.createTransport({
      ...baseOptions,
      secure: SMTP_SECURE,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      }
    })
  } else {
    // Local / direct delivery fallback
    transporter = nodemailer.createTransport({
      ...baseOptions,
      secure: false
    })
  }
  return transporter
}

export async function sendAuthCodeEmail(email, code) {
  const subject = `Код подтверждения TIIN Finance: ${code}`
  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; background: #0f172a; color: #f8fafc; border-radius: 16px; border: 1px solid #334155;">
      <div style="text-align: center; margin-bottom: 24px;">
        <h2 style="color: #818cf8; margin: 0 0 8px; font-size: 24px; font-weight: 800;">TIIN Finance</h2>
        <p style="color: #94a3b8; margin: 0; font-size: 14px;">Безопасный вход и синхронизация</p>
      </div>

      <div style="background: #1e293b; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px; border: 1px solid #334155;">
        <div style="color: #94a3b8; font-size: 13px; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px;">Ваш одноразовый код:</div>
        <div style="font-size: 36px; font-weight: 800; letter-spacing: 6px; color: #38bdf8; font-family: monospace;">${code}</div>
        <div style="color: #f43f5e; font-size: 12px; margin-top: 12px;">Срок действия кода: 5 минут</div>
      </div>

      <p style="color: #94a3b8; font-size: 13px; line-height: 1.5; margin: 0 0 12px;">
        Если вы не запрашивали данный код, просто проигнорируйте это письмо. Никому не сообщайте полученный код.
      </p>

      <div style="border-top: 1px solid #334155; padding-top: 16px; text-align: center; color: #64748b; font-size: 11px;">
        TIIN Finance • Персональный учет бюджета
      </div>
    </div>
  `

  console.log(`[Auth Code] Generated for ${email}: ${code}`)

  try {
    const t = getTransporter()
    await t.sendMail({
      from: SMTP_FROM,
      to: email,
      subject,
      html,
      text: `Ваш код подтверждения TIIN Finance: ${code} (действует 5 минут).`
    })
    console.log(`[Email] Auth code successfully sent to ${email}`)
    return { success: true }
  } catch (err) {
    console.warn(`[Email Warning] Could not send email to ${email} via SMTP: ${err.message}`)
    // If Telegram Bot is available and admin ID is set, notify admin for fallback testing
    if (process.env.TELEGRAM_BOT_TOKEN && process.env.ADMIN_TG_ID) {
      try {
        const tgMsg = encodeURIComponent(`🔐 Код авторизации TIIN Finance для ${email}: *${code}*`)
        await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage?chat_id=${process.env.ADMIN_TG_ID}&text=${tgMsg}&parse_mode=Markdown`)
      } catch {}
    }
    return { success: false, fallback: true, message: err.message }
  }
}

export async function sendBackupEmail(email, buffer, filename, stats = {}) {
  const subject = `Резервная копия бюджета TIIN Finance (${new Date().toLocaleDateString('ru-RU')})`
  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; background: #0f172a; color: #f8fafc; border-radius: 16px; border: 1px solid #334155;">
      <div style="text-align: center; margin-bottom: 24px;">
        <h2 style="color: #818cf8; margin: 0 0 8px; font-size: 24px; font-weight: 800;">TIIN Finance</h2>
        <p style="color: #94a3b8; margin: 0; font-size: 14px;">Регулярная резервная копия ваших данных</p>
      </div>

      <div style="background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 24px; border: 1px solid #334155;">
        <p style="margin: 0 0 10px; font-size: 14px; color: #e2e8f0;">Здравствуйте! Во вложении свежая выгрузка вашего бюджета.</p>
        <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #94a3b8; line-height: 1.6;">
          <li>Транзакций: <strong>${stats.txCount || 0}</strong></li>
          <li>Категорий: <strong>${stats.catCount || 0}</strong></li>
          <li>Целей накоплений: <strong>${stats.goalCount || 0}</strong></li>
          <li>Дата формирования: <strong>${new Date().toLocaleString('ru-RU')}</strong></li>
        </ul>
      </div>

      <p style="color: #64748b; font-size: 12px; margin: 0; text-align: center;">
        Настроить частоту отправки или отключить бэкапы можно в приложении в меню профиля.
      </p>
    </div>
  `

  try {
    const t = getTransporter()
    await t.sendMail({
      from: SMTP_FROM,
      to: email,
      subject,
      html,
      attachments: [
        {
          filename,
          content: buffer
        }
      ]
    })
    console.log(`[Backup Email] Successfully sent backup to ${email}`)
    return { success: true }
  } catch (err) {
    console.error(`[Backup Email Error] Failed to send backup to ${email}:`, err.message)
    return { success: false, error: err.message }
  }
}
