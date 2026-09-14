import express from 'express'
import cors from 'cors'
import path from 'path'
import { fileURLToPath } from 'url'
import multer from 'multer'
import crypto from 'crypto'
import { spawn } from 'child_process'
import fs from 'fs/promises'
import pool from './db.js'
import {
  hashPassword, verifyPassword, signToken,
  authMiddleware, optionalAuthMiddleware, adminMiddleware, instanceMiddleware, instanceOwnerMiddleware
} from './auth.js'
import {
  initDemoAccounts, getDemoSlotsStatus, occupyDemoSlot, releaseDemoSlot,
  clearDemoInstanceData, seedDemoInstanceData, cleanupExpiredDemoSessions
} from './demo.js'
import XLSX from 'xlsx'
import { createRequire } from 'module'
const require = createRequire(import.meta.url)
import { createRateLimiter, clearRateLimit, sanitizeUsername } from './rate-limiter.js'
import { PLANS, getUserPlanInfo, getUserUsage } from './plans.js'



const __dirname = path.dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = process.env.PORT || 3000

app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname, '../public')))

// Favicon fallback route
app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/favicon.png'))
})

// ==================== RATE LIMITERS & SECURITY ====================

const loginLimiter = createRateLimiter({
  prefix: 'login',
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxAttempts: 5,
  message: 'Слишком много неудачных попыток входа. Пожалуйста, подождите 15 минут.'
})

const registerLimiter = createRateLimiter({
  prefix: 'register',
  windowMs: 60 * 60 * 1000, // 1 hour
  maxAttempts: 5,
  message: 'Превышен лимит регистраций с вашего IP. Попробуйте позже.'
})

const forgotPasswordLimiter = createRateLimiter({
  prefix: 'forgot_password',
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxAttempts: 3,
  message: 'Слишком много запросов на сброс пароля. Подождите 15 минут.'
})

// Fake password verification hash for timing attack protection
const DUMMY_PASSWORD_HASH = '$2b$12$e09a3qXjO6L/s5bM55F0.uH9iK3R/7iH3H9nL2m3j4k5l6m7n8o9p'

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', registerLimiter, async (req, res) => {
  try {
    const rawUsername = req.body.username
    const password = req.body.password
    const username = sanitizeUsername(rawUsername)

    if (!username || !password) return res.status(400).json({ error: 'Требуется имя пользователя и пароль' })
    if (username.length < 3 || username.length > 32) {
      return res.status(400).json({ error: 'Имя пользователя должно содержать от 3 до 32 символов' })
    }
    if (password.length < 6) return res.status(400).json({ error: 'Пароль должен состоять минимум из 6 символов' })

    const passwordHash = await hashPassword(password)
    const { rows } = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, is_admin',
      [username, passwordHash]
    )
    const token = signToken({ id: rows[0].id, username: rows[0].username, is_admin: rows[0].is_admin })
    res.status(201).json({ user: rows[0], token })
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Имя пользователя уже занято' })
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const rawUsername = req.body.username
    const password = req.body.password
    const username = sanitizeUsername(rawUsername)

    if (!username || !password) return res.status(400).json({ error: 'Требуется имя пользователя и пароль' })

    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username])
    
    // Protection against Timing Attack
    if (!rows.length) {
      await verifyPassword(password, DUMMY_PASSWORD_HASH).catch(() => {})
      return res.status(401).json({ error: 'Неверные учетные данные' })
    }

    const user = rows[0]
    const valid = await verifyPassword(password, user.password)
    if (!valid) return res.status(401).json({ error: 'Неверные учетные данные' })

    // Clear rate limit on successful authentication
    clearRateLimit('login', req)

    const token = signToken({ id: user.id, username: user.username, is_admin: user.is_admin })
    res.json({ user: { id: user.id, username: user.username, is_admin: user.is_admin }, token })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Telegram WebApp Auto-Login
function validateTelegramWebAppData(initData, botToken) {
  if (!initData || !botToken) return null
  try {
    const params = new URLSearchParams(initData)
    const hash = params.get('hash')
    if (!hash) return null
    params.delete('hash')

    const dataCheckArr = []
    for (const [key, value] of params.entries()) {
      dataCheckArr.push(`${key}=${value}`)
    }
    dataCheckArr.sort()
    const dataCheckString = dataCheckArr.join('\n')

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest()
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex')

    if (calculatedHash !== hash) return null

    const userStr = params.get('user')
    return userStr ? JSON.parse(userStr) : null
  } catch (err) {
    return null
  }
}

app.post('/api/auth/telegram-webapp', async (req, res) => {
  try {
    const { initData } = req.body
    const botToken = process.env.TELEGRAM_BOT_TOKEN
    if (!initData || !botToken) {
      return res.status(400).json({ error: 'initData and BOT_TOKEN required' })
    }
    const tgUser = validateTelegramWebAppData(initData, botToken)
    if (!tgUser || !tgUser.id) {
      return res.status(401).json({ error: 'Неверная подпись Telegram WebApp' })
    }

    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.is_admin, tfi.instance_id
       FROM telegram_finance_instances tfi
       JOIN instances i ON i.id = tfi.instance_id
       JOIN users u ON u.id = i.owner_id
       WHERE tfi.tg_id = $1`,
      [tgUser.id]
    )

    if (!rows.length) {
      return res.status(404).json({ error: 'Telegram аккаунт не привязан к инстансу' })
    }

    const u = rows[0]
    const token = signToken({ id: u.id, username: u.username, is_admin: u.is_admin })
    res.json({
      token,
      user: { id: u.id, username: u.username, is_admin: u.is_admin },
      instance_id: u.instance_id
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


// ==================== PASSWORD RESET ====================

// Ensure password reset requests table
pool.query(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    contact_info TEXT NOT NULL,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'completed')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '1 hour')
  )
`).catch(console.error)

app.post('/api/auth/forgot-password', forgotPasswordLimiter, async (req, res) => {
  try {
    const rawUsername = req.body?.username
    const contact = req.body?.contact
    const username = sanitizeUsername(rawUsername)

    if (!username || !contact) {
      return res.status(400).json({ error: 'Укажите Ваш логин и контакт (Telegram / Email) для восстановления' })
    }


    const { rows: users } = await pool.query('SELECT id, username FROM users WHERE username = $1', [username])
    if (!users.length) {
      return res.status(404).json({ error: 'Пользователь с таким логином не найден' })
    }
    const user = users[0]

    // Generate 6-digit numeric recovery code
    const code = String(Math.floor(100000 + Math.random() * 900000))

    await pool.query(
      `INSERT INTO password_resets (user_id, code, contact_info) VALUES ($1, $2, $3)`,
      [user.id, code, String(contact).trim()]
    )

    // Notify Admin in Telegram to send code / confirm user
    const botToken = process.env.TELEGRAM_BOT_TOKEN
    const adminId = process.env.ADMIN_TG_ID
    if (botToken && adminId) {
      const msg = `🔑 *ЗАПРОС НА СБРОС ПАРОЛЯ*\n\n` +
                  `👤 Логин: \`${user.username}\`\n` +
                  `📞 Контакт: \`${contact}\`\n` +
                  `🔢 Код восстановления: \`${code}\`\n\n` +
                  `Передайте код пользователю или подтвердите сброс в /admin!`
      fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: adminId, text: msg, parse_mode: 'Markdown' })
      }).catch(err => console.error('Failed to notify Telegram reset:', err))
    }

    res.json({
      ok: true,
      message: 'Запрос принят! Код восстановления или ссылка отправлены разработчику. Свяжитесь для подтверждения.'
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { username, code, new_password } = req.body || {}
    if (!username || !code || !new_password) {
      return res.status(400).json({ error: 'Заполните логин, код и новый пароль' })
    }
    if (new_password.length < 6) {
      return res.status(400).json({ error: 'Пароль должен состоять минимум из 6 символов' })
    }

    const { rows: users } = await pool.query('SELECT id FROM users WHERE username = $1', [username])
    if (!users.length) {
      return res.status(404).json({ error: 'Пользователь не найден' })
    }
    const user = users[0]

    const { rows: resets } = await pool.query(
      `SELECT * FROM password_resets
       WHERE user_id = $1 AND code = $2 AND status = 'pending' AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [user.id, String(code).trim()]
    )

    if (!resets.length) {
      return res.status(400).json({ error: 'Неверный или просроченный код восстановления' })
    }

    const newHash = await hashPassword(new_password)
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [newHash, user.id])
    await pool.query("UPDATE password_resets SET status = 'completed' WHERE id = $1", [resets[0].id])

    res.json({ ok: true, message: 'Пароль успешно изменен! Теперь Вы можете войти с новым паролем.' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, is_admin, plan, plan_expires_at FROM users WHERE id = $1', [req.user.id]
    )
    if (!rows.length) return res.status(404).json({ error: 'Пользователь не найден' })
    
    // Check if demo user & attach demo session info
    let demoInfo = null
    if (req.user.is_demo) {
      const demoRes = await pool.query('SELECT slot_number, expires_at, receipt_scans_left FROM demo_sessions WHERE user_id = $1', [req.user.id])
      if (demoRes.rows.length) {
        const ds = demoRes.rows[0]
        demoInfo = {
          is_demo: true,
          slot: ds.slot_number,
          expires_at: ds.expires_at,
          seconds_remaining: Math.max(0, Math.floor((new Date(ds.expires_at).getTime() - Date.now()) / 1000)),
          receipt_scans_left: ds.receipt_scans_left
        }
      }
    }

    const planInfo = req.user.is_demo ? {
      code: 'demo',
      name: 'Демо-доступ',
      badge: '🎮 Demo',
      expires_at: demoInfo?.expires_at,
      limits: {
        maxInstances: 1,
        maxTransactions: 30,
        monthlyReceiptScans: 3,
        monthlyAiAdvices: 0,
        maxMembers: 1,
        allowImportXlsx: false,
        allowAiAdvisor: false
      }
    } : await getUserPlanInfo(req.user.id)

    res.json({
      ...rows[0],
      is_demo: !!req.user.is_demo,
      demo: demoInfo,
      plan_info: planInfo
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/user/plan', authMiddleware, async (req, res) => {
  try {
    if (req.user.is_demo) {
      return res.json({
        plan: {
          code: 'demo',
          name: 'Демо-доступ',
          badge: '🎮 Demo'
        },
        limits: {
          maxInstances: 1,
          maxTransactions: 30,
          monthlyReceiptScans: 3,
          monthlyAiAdvices: 0,
          maxMembers: 1,
          allowImportXlsx: false,
          allowAiAdvisor: false
        },
        usage: {
          instancesCount: 1,
          instanceTransactionsCount: 0,
          receiptScansMonth: 0,
          aiAdvicesMonth: 0
        },
        all_plans: PLANS
      })
    }

    const instanceId = req.query.instance_id ? parseInt(req.query.instance_id) : null
    const planInfo = await getUserPlanInfo(req.user.id)
    const usage = await getUserUsage(req.user.id, instanceId)

    res.json({
      plan: planInfo,
      usage,
      all_plans: PLANS
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== DEMO MODE ROUTES ====================

app.get('/api/demo/slots', async (req, res) => {
  try {
    const slots = await getDemoSlotsStatus()
    res.json({ slots })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/demo/login', async (req, res) => {
  try {
    const { slot } = req.body || {}
    const result = await occupyDemoSlot(slot ? parseInt(slot) : null)
    if (!result.success) {
      return res.status(409).json({ error: result.error })
    }
    res.json(result)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/demo/logout', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_demo) {
      return res.status(400).json({ error: 'Не является гостевым аккаунтом' })
    }
    await releaseDemoSlot(req.user.id)
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/demo/seed', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    if (!req.user.is_demo) {
      return res.status(403).json({ error: 'Доступно только в демо-режиме' })
    }
    await seedDemoInstanceData(req.instanceId)
    res.json({ ok: true, message: 'Живые демо-данные успешно сгенерированы!' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/demo/clear', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    if (!req.user.is_demo) {
      return res.status(403).json({ error: 'Доступно только в демо-режиме' })
    }
    await clearDemoInstanceData(req.instanceId)
    res.json({ ok: true, message: 'Демо-данные успешно очищены!' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


// ==================== DONATION & EARLY ACCESS ROUTES ====================

// Ensure table exists
pool.query(`
  CREATE TABLE IF NOT EXISTS donation_requests (
    id SERIAL PRIMARY KEY,
    desired_username TEXT NOT NULL,
    contact_info TEXT NOT NULL,
    donation_amount NUMERIC(10,2),
    comment TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )
`).catch(console.error)

const TOTAL_DONATION_SPOTS = 10

app.get('/api/donations/stats', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT COUNT(*) as taken FROM donation_requests')
    const taken = parseInt(rows[0].taken || '0')
    const remaining = Math.max(0, TOTAL_DONATION_SPOTS - taken)
    res.json({
      total_spots: TOTAL_DONATION_SPOTS,
      taken_spots: taken,
      remaining_spots: remaining
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/donations/apply', async (req, res) => {
  try {
    const { desired_username, contact_info, donation_amount, comment } = req.body || {}
    if (!desired_username || !contact_info) {
      return res.status(400).json({ error: 'Заполните желаемый логин и контакт для связи' })
    }

    const { rows: checkCount } = await pool.query('SELECT COUNT(*) as taken FROM donation_requests')
    const taken = parseInt(checkCount[0].taken || '0')
    if (taken >= TOTAL_DONATION_SPOTS) {
      return res.status(400).json({ error: 'К сожалению, все 10 мест уже забронированы!' })
    }

    await pool.query(
      `INSERT INTO donation_requests (desired_username, contact_info, donation_amount, comment)
       VALUES ($1, $2, $3, $4)`,
      [
        String(desired_username).trim(),
        String(contact_info).trim(),
        donation_amount ? parseFloat(donation_amount) : null,
        comment ? String(comment).trim() : ''
      ]
    )

    // Send Telegram alert if tokens exist
    const botToken = process.env.TELEGRAM_BOT_TOKEN
    const adminId = process.env.ADMIN_TG_ID
    if (botToken && adminId) {
      const msg = `🎁 *НОВАЯ ЗАЯВКА НА ПОЖИЗНЕННЫЙ ДОСТУП*\n\n` +
                  `👤 Логин: \`${desired_username}\`\n` +
                  `📞 Контакт: \`${contact_info}\`\n` +
                  `💰 Донат: \`${donation_amount || 'Не указана'} ₽\`\n` +
                  `💬 Комментарий: ${comment || 'Без комментария'}\n\n` +
                  `Занято мест: ${taken + 1} / ${TOTAL_DONATION_SPOTS}`
      fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: adminId, text: msg, parse_mode: 'Markdown' })
      }).catch(err => console.error('Failed to notify Telegram:', err))
    }
    res.json({ ok: true, message: 'Заявка принята! Ожидайте связку и вечный ключ в Telegram/Email.' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


app.get('/api/admin/donations', authMiddleware, adminMiddleware, async (req, res) => {

  try {
    const { rows } = await pool.query('SELECT * FROM donation_requests ORDER BY created_at DESC')
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/admin/donations/:id/approve', authMiddleware, adminMiddleware, async (req, res) => {
  const donationId = parseInt(req.params.id)
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const { rows: don } = await client.query('SELECT * FROM donation_requests WHERE id = $1', [donationId])
    if (!don.length) {
      await client.query('ROLLBACK')
      return res.status(404).json({ error: 'Заявка не найдена' })
    }
    const d = don[0]

    // Generate random secure password
    const rawPassword = 'Tn_' + Math.random().toString(36).slice(-6) + '!'
    const passwordHash = await hashPassword(rawPassword)

    // Create user
    const { rows: uRows } = await client.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [d.desired_username, passwordHash]
    )
    const newUser = uRows[0]

    // Create personal instance
    const { rows: iRows } = await client.query(
      'INSERT INTO instances (name, owner_id) VALUES ($1, $2) RETURNING id, name',
      ['Личный бюджет', newUser.id]
    )
    await client.query(
      'INSERT INTO instance_members (instance_id, user_id, role) VALUES ($1, $2, \'owner\')',
      [iRows[0].id, newUser.id]
    )

    await client.query('COMMIT')

    // Send Telegram notice with ready credentials to admin
    const botToken = process.env.TELEGRAM_BOT_TOKEN
    const adminId = process.env.ADMIN_TG_ID
    if (botToken && adminId) {
      const msg = `🎉 *АККАУНТ ДЛЯ ДОНАТОРА СОЗДАН!*\n\n` +
                  `Контакт: \`${d.contact_info}\`\n` +
                  `Логин: \`${newUser.username}\`\n` +
                  `Пароль: \`${rawPassword}\`\n\n` +
                  `Отправьте эти данные пользователю в Telegram/Email!`
      fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: adminId, text: msg, parse_mode: 'Markdown' })
      }).catch(err => console.error(err))
    }

    res.json({
      ok: true,
      credentials: {
        username: newUser.username,
        password: rawPassword
      }
    })
  } catch (err) {
    await client.query('ROLLBACK')
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Пользователь с таким логином уже существует в системе' })
    }
    res.status(500).json({ error: err.message })
  } finally {
    client.release()
  }
})




// Analytics Tracking
app.post('/api/analytics/track', authMiddleware, async (req, res) => {
  try {
    const { action_type, entity_type, entity_id, instance_id } = req.body
    if (!action_type) return res.status(400).json({ error: 'Action type required' })
    
    await pool.query(
      'INSERT INTO user_actions_log (user_id, instance_id, action_type, entity_type, entity_id) VALUES ($1, $2, $3, $4, $5)',
      [req.user.id, instance_id || null, action_type, entity_type || null, entity_id ? String(entity_id) : null]
    )
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== INSTANCE ROUTES ====================

app.post('/api/instances', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body
    if (!name) return res.status(400).json({ error: 'Требуется имя инстанса' })
    if (req.user.is_demo) {
      return res.status(403).json({ error: 'В демо-режиме создание дополнительных бюджетов недоступно.' })
    }

    const planInfo = await getUserPlanInfo(req.user.id)
    if (!planInfo.is_admin) {
      const { rows: instCountRows } = await pool.query(
        `SELECT COUNT(*) FROM instance_members WHERE user_id = $1 AND role = 'owner'`,
        [req.user.id]
      )
      const currentCount = parseInt(instCountRows[0].count) || 0
      if (currentCount >= planInfo.limits.maxInstances) {
        return res.status(403).json({
          error: `Достигнут лимит бюджетов (${planInfo.limits.maxInstances}) для тарифа "${planInfo.name}". Перейдите на более высокий тариф для создания новых бюджетов.`
        })
      }
    }
    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      const { rows: instRows } = await client.query(
        'INSERT INTO instances (name, owner_id) VALUES ($1, $2) RETURNING *',
        [name, req.user.id]
      )
      await client.query(
        'INSERT INTO instance_members (instance_id, user_id, role) VALUES ($1, $2, $3)',
        [instRows[0].id, req.user.id, 'owner']
      )
      await client.query('COMMIT')
      res.status(201).json(instRows[0])
    } catch (err) {
      await client.query('ROLLBACK')
      throw err
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/telegram-instances/:tgId', authMiddleware, async (req, res) => {
  try {
    const { tgId } = req.params
    const { rows } = await pool.query('SELECT instance_id FROM telegram_finance_instances WHERE tg_id = $1', [tgId])
    if (!rows.length) return res.status(404).json({ error: 'Instance not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/telegram-instances', authMiddleware, async (req, res) => {
  try {
    const { tg_id, instance_id } = req.body
    if (!tg_id || !instance_id) return res.status(400).json({ error: 'tg_id and instance_id required' })
    const { rows } = await pool.query(
      'INSERT INTO telegram_finance_instances (tg_id, instance_id) VALUES ($1, $2) ON CONFLICT (tg_id) DO UPDATE SET instance_id = EXCLUDED.instance_id RETURNING *',
      [tg_id, instance_id]
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


app.get('/api/instances', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT i.id, i.name, i.created_at, m.role,
              EXISTS(SELECT 1 FROM telegram_finance_instances tfi WHERE tfi.instance_id = i.id) as is_telegram_linked
       FROM instances i
       JOIN instance_members m ON m.instance_id = i.id
       WHERE m.user_id = $1
       ORDER BY i.created_at DESC`,
      [req.user.id]
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


app.get('/api/instances/:instanceId', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM instances WHERE id = $1', [req.instanceId])
    if (!rows.length) return res.status(404).json({ error: 'Инстанс не найден' })
    res.json({ ...rows[0], role: req.memberRole })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM instances WHERE id = $1', [req.instanceId])
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/instances/:instanceId', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    const { name } = req.body
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'Требуется имя инстанса' })
    const { rows } = await pool.query('UPDATE instances SET name = $1 WHERE id = $2 RETURNING *', [String(name).trim(), req.instanceId])
    if (!rows.length) return res.status(404).json({ error: 'Инстанс не найден' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

const upload = multer({ dest: '/app/uploaded/' })

// ==================== RECEIPT ROUTES ====================

app.post('/api/instances/:instanceId/upload-receipt', authMiddleware, instanceMiddleware, upload.single('receipt'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image uploaded' })
  try {
    if (req.user.is_demo) {
      const demoRes = await pool.query('SELECT receipt_scans_left FROM demo_sessions WHERE user_id = $1', [req.user.id])
      if (demoRes.rows.length) {
        const left = demoRes.rows[0].receipt_scans_left
        if (left <= 0) {
          return res.status(429).json({ error: 'Достигнут лимит 3 сканирований чеков для демо-сессии.' })
        }
        await pool.query('UPDATE demo_sessions SET receipt_scans_left = receipt_scans_left - 1 WHERE user_id = $1', [req.user.id])
      }
    } else {
      const planInfo = await getUserPlanInfo(req.user.id)
      if (!planInfo.is_admin) {
        const { rows: scanRows } = await pool.query(
          `SELECT COUNT(*) FROM user_actions_log
           WHERE user_id = $1 AND action_type = 'scan_receipt'
             AND created_at >= date_trunc('month', CURRENT_DATE)`,
          [req.user.id]
        )
        const currentScans = parseInt(scanRows[0].count) || 0
        if (currentScans >= planInfo.limits.monthlyReceiptScans) {
          return res.status(429).json({
            error: `Достигнут ежемесячный лимит ${planInfo.limits.monthlyReceiptScans} сканирований чеков для тарифа "${planInfo.name}".`
          })
        }
      }
    }

    const script = spawn('python3', ['/app/scripts/scan_receipt.py', '--url', req.file.path], {
      env: {
        ...process.env,
        FINANCE_API_URL: 'http://127.0.0.1:3000',
        FINANCE_JWT: req.headers.authorization.split(' ')[1],
        FINANCE_INSTANCE_ID: req.instanceId
      }
    })
    let stdout = '', stderr = ''
    script.stdout.on('data', data => stdout += data)
    script.stderr.on('data', data => stderr += data)
    script.on('close', async (code) => {
      if (code !== 0) {
        try {
          const result = JSON.parse(stdout)
          if (result.error) return res.status(500).json({ error: result.error, stderr, image_path: req.file.path, raw: stdout })
        } catch (e) {}
        return res.status(500).json({ error: 'Scan failed', stderr, raw: stdout, image_path: req.file.path })
      }
      try {
        const result = JSON.parse(stdout)
        // Log action
        if (!req.user.is_demo) {
          await pool.query(
            `INSERT INTO user_actions_log (user_id, instance_id, action_type, entity_type) VALUES ($1, $2, 'scan_receipt', 'receipt')`,
            [req.user.id, req.instanceId]
          ).catch(console.error)
        }
        res.json({ ...result, image_path: req.file.path })
      } catch (e) {
        res.status(500).json({ error: 'Failed to parse scan result', raw: stdout, image_path: req.file.path })
      }
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/report-scanner-issue', authMiddleware, instanceMiddleware, async (req, res) => {
  const { description, image_path, logs } = req.body
  try {
    const filename = path.basename(image_path)
    const newPath = path.join('/app/uploaded/emergency/', filename)
    await fs.rename(image_path, newPath)
    
    // Send to Telegram if tokens are present
    const botToken = process.env.TELEGRAM_BOT_TOKEN
    const adminId = process.env.ADMIN_TG_ID
    if (botToken && adminId) {
      const form = new FormData()
      form.append('chat_id', adminId)
      const caption = `🚨 Ошибка сканирования чека\nПользователь: ${req.user.username}\n\nЛоги:\n${(logs || '').substring(0, 800)}`
      form.append('caption', caption)
      
      const fileBuffer = await fs.readFile(newPath)
      const blob = new Blob([fileBuffer], { type: 'image/jpeg' })
      form.append('photo', blob, filename)
      
      const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendPhoto`, {
        method: 'POST',
        body: form
      })
      if (!tgRes.ok) {
        console.error('Failed to send to Telegram:', await tgRes.text())
      }
    }
    
    console.error(`ERROR: Scanner Issue Reported. User: ${req.user.username}. Description: ${description}. Image: ${newPath}`)
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/join', authMiddleware, async (req, res) => {
  try {
    if (req.user.is_demo) {
      return res.status(403).json({ error: 'Демо-пользователи не могут присоединяться к другим инстансам' })
    }
    const instanceId = parseInt(req.params.instanceId)
    const { rows: instCheck } = await pool.query('SELECT id FROM instances WHERE id = $1', [instanceId])
    if (!instCheck.length) return res.status(404).json({ error: 'Инстанс не найден' })
    const { rows: memberCheck } = await pool.query(
      'SELECT 1 FROM instance_members WHERE instance_id = $1 AND user_id = $2',
      [instanceId, req.user.id]
    )
    if (memberCheck.length) return res.status(409).json({ error: 'Уже участник' })
    const { rows: reqCheck } = await pool.query(
      "SELECT 1 FROM join_requests WHERE instance_id = $1 AND user_id = $2 AND status = 'pending'",
      [instanceId, req.user.id]
    )
    if (reqCheck.length) return res.status(409).json({ error: 'Запрос уже ожидает рассмотрения' })
    await pool.query(
      'INSERT INTO join_requests (instance_id, user_id) VALUES ($1, $2)',
      [instanceId, req.user.id]
    )
    res.status(201).json({ ok: true, message: 'Join request sent' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/instances/:instanceId/requests', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT jr.id, jr.user_id, u.username, jr.status, jr.created_at
       FROM join_requests jr
       JOIN users u ON u.id = jr.user_id
       WHERE jr.instance_id = $1 AND jr.status = 'pending'
       ORDER BY jr.created_at ASC`,
      [req.instanceId]
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/requests/:requestId/approve', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    const requestId = parseInt(req.params.requestId)
    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      const { rows } = await client.query(
        "UPDATE join_requests SET status = 'approved', resolved_at = NOW() WHERE id = $1 AND instance_id = $2 AND status = 'pending' RETURNING user_id",
        [requestId, req.instanceId]
      )
      if (!rows.length) {
        await client.query('ROLLBACK')
        return res.status(404).json({ error: 'Запрос не найден или уже обработан' })
      }
      // Check instance owner plan member limit
      const ownerPlanInfo = await getUserPlanInfo(req.user.id)
      if (!ownerPlanInfo.is_admin) {
        const { rows: memberCountRows } = await client.query(
          'SELECT COUNT(*) FROM instance_members WHERE instance_id = $1',
          [req.instanceId]
        )
        const currentMembers = parseInt(memberCountRows[0].count) || 0
        if (currentMembers >= ownerPlanInfo.limits.maxMembers) {
          await client.query('ROLLBACK')
          return res.status(403).json({
            error: `Достигнут лимит участников (${ownerPlanInfo.limits.maxMembers}) для тарифа "${ownerPlanInfo.name}". Для совместного доступа перейдите на тариф "Семья & Бизнес".`
          })
        }
      }

      await client.query(
        'INSERT INTO instance_members (instance_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
        [req.instanceId, rows[0].user_id, 'member']
      )
      await client.query('COMMIT')
      res.json({ ok: true })
    } catch (err) {
      await client.query('ROLLBACK')
      throw err
    } finally {
      client.release()
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/requests/:requestId/reject', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    const requestId = parseInt(req.params.requestId)
    const { rows } = await pool.query(
      "UPDATE join_requests SET status = 'rejected', resolved_at = NOW() WHERE id = $1 AND instance_id = $2 AND status = 'pending' RETURNING id",
      [requestId, req.instanceId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Запрос не найден или уже обработан' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== MEMBER ROUTES ====================

app.get('/api/instances/:instanceId/members', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT m.id, m.user_id, u.username, m.role, m.joined_at
       FROM instance_members m
       JOIN users u ON u.id = m.user_id
       WHERE m.instance_id = $1
       ORDER BY m.role, m.joined_at ASC`,
      [req.instanceId]
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/members/:userId', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId)
    if (userId === req.user.id) return res.status(400).json({ error: 'Нельзя удалить самого себя. Вместо этого удалите инстанс.' })
    const { rowCount } = await pool.query(
      "DELETE FROM instance_members WHERE instance_id = $1 AND user_id = $2 AND role != 'owner'",
      [req.instanceId, userId]
    )
    if (!rowCount) return res.status(404).json({ error: 'Участник не найден или является владельцем' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== ACCOUNTS ROUTES ====================

app.get('/api/instances/:instanceId/accounts', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT a.id, a.name, a.currency, a.type, a.created_at,
         COALESCE((SELECT SUM(CASE WHEN t.type='income' THEN t.amount ELSE -t.amount END) FROM transactions t WHERE t.account_id = a.id AND (t.is_planned IS FALSE OR t.is_planned IS NULL)), 0) as balance
       FROM accounts a
       WHERE a.instance_id = $1
       ORDER BY a.created_at ASC`,
      [req.instanceId]
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


app.post('/api/instances/:instanceId/accounts', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, currency, type } = req.body
    if (!name || !name.trim()) return res.status(400).json({ error: 'Требуется название счета' })
    const { rows } = await pool.query(
      'INSERT INTO accounts (name, currency, type, instance_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [name.trim(), currency || 'RUB', type || 'card', req.instanceId]
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/instances/:instanceId/accounts/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, currency, type } = req.body
    const { rows } = await pool.query(
      'UPDATE accounts SET name = COALESCE($1, name), currency = COALESCE($2, currency), type = COALESCE($3, type) WHERE id = $4 AND instance_id = $5 RETURNING *',
      [name ? name.trim() : null, currency, type, req.params.id, req.instanceId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Счет не найден' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/accounts/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM accounts WHERE id = $1 AND instance_id = $2',
      [req.params.id, req.instanceId]
    )
    if (!rowCount) return res.status(404).json({ error: 'Счет не найден' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== TRANSACTIONS ROUTES ====================

const SERVICE_CATEGORY_NAMES = new Set(['Цели', 'Свободные накопления', 'накопления', 'кредиты', 'без классификации', 'доход', ''])

async function resolveCategoryId(db, instanceId, name, type) {
  if (!name) return null
  const r = await db.query('SELECT id FROM categories WHERE instance_id = $1 AND name = $2', [instanceId, name])
  if (r.rows.length) return r.rows[0].id
  const g = await db.query('SELECT id, type FROM categories WHERE instance_id IS NULL AND name = $1', [name])
  const catType = type || g.rows[0]?.type || 'expense'
  const ins = await db.query(
    'INSERT INTO categories (name, type, instance_id, is_default) VALUES ($1, $2, $3, FALSE) RETURNING id',
    [name, catType, instanceId]
  )
  return ins.rows[0].id
}

const CATEGORY_SELECT = 't.*, c.name AS category'
const CATEGORY_JOIN = 'LEFT JOIN categories c ON c.id = t.category_id'

app.get('/api/instances/:instanceId/transactions', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { category_id, exclude_category_id, type, exclude_type, is_planned, from, to, search, limit = 100, offset = 0 } = req.query
    const conditions = ['t.instance_id = $1']
    const params = [req.instanceId]
    let i = 2
    if (category_id) { conditions.push(`t.category_id = $${i++}`); params.push(category_id) }
    if (exclude_category_id) { conditions.push(`t.category_id != $${i++}`); params.push(exclude_category_id) }
    if (type) { conditions.push(`t.type = $${i++}`); params.push(type) }
    if (exclude_type) { conditions.push(`t.type != $${i++}`); params.push(exclude_type) }
    if (from) { conditions.push(`t.date >= $${i++}`); params.push(from) }
    if (to) { conditions.push(`t.date <= $${i++}`); params.push(to) }
    if (is_planned === 'true') { conditions.push(`t.is_planned = TRUE`) }
    else if (is_planned !== undefined) { conditions.push(`t.is_planned = FALSE`) }
    if (search) { conditions.push(`t.name ILIKE $${i++}`); params.push(`%${search}%`) }
    const where = `WHERE ${conditions.join(' AND ')}`
    params.push(parseInt(limit), parseInt(offset))
    const { rows } = await pool.query(
      `SELECT ${CATEGORY_SELECT} FROM transactions t ${CATEGORY_JOIN} ${where} ORDER BY t.date DESC, t.id LIMIT $${i++} OFFSET $${i++}`,
      params
    )
    const { rows: countRows } = await pool.query(
      `SELECT COUNT(*) FROM transactions t ${where}`,
      params.slice(0, -2)
    )
    res.json({ data: rows, total: parseInt(countRows[0].count) })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/instances/:instanceId/transactions/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ${CATEGORY_SELECT} FROM transactions t ${CATEGORY_JOIN} WHERE t.id = $1 AND t.instance_id = $2`,
      [req.params.id, req.instanceId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Не найдено' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Check potential duplicate transactions
app.post('/api/instances/:instanceId/transactions/check-duplicates', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { items } = req.body
    if (!Array.isArray(items) || !items.length) {
      return res.json({ duplicates: [] })
    }

    const duplicates = []

    for (const item of items) {
      if (!item.amount || !item.date) continue
      
      const itemDate = item.date.slice(0, 10)
      const itemAmount = parseFloat(item.amount)
      const itemQty = item.quantity ? parseFloat(item.quantity) : null

      let query = `
        SELECT id, name, date, amount, price, quantity
        FROM transactions
        WHERE instance_id = $1
          AND date::text LIKE $2
          AND ABS(amount - $3) < 0.01
      `
      const params = [req.instanceId, `${itemDate}%`, itemAmount]
      let idx = 4

      if (itemQty !== null) {
        query += ` AND (quantity IS NOT NULL AND ABS(quantity - $${idx++}) < 0.001)`
        params.push(itemQty)
      }

      const { rows } = await pool.query(query, params)
      if (rows.length > 0) {
        duplicates.push({
          item,
          existing: rows[0]
        })
      }
    }

    res.json({ duplicates })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/transactions', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    if (req.user.is_demo) {
      const { rows: txCountRows } = await pool.query(
        'SELECT COUNT(*) FROM transactions WHERE instance_id = $1',
        [req.instanceId]
      )
      if (parseInt(txCountRows[0].count) >= 30) {
        return res.status(403).json({ error: 'Достигнут лимит 30 транзакций для демо-сессии.' })
      }
    } else {
      const planInfo = await getUserPlanInfo(req.user.id)
      if (!planInfo.is_admin && Number.isFinite(planInfo.limits.maxTransactions)) {
        const { rows: txCountRows } = await pool.query(
          'SELECT COUNT(*) FROM transactions WHERE instance_id = $1',
          [req.instanceId]
        )
        const count = parseInt(txCountRows[0].count) || 0
        if (count >= planInfo.limits.maxTransactions) {
          return res.status(403).json({
            error: `Достигнут лимит ${planInfo.limits.maxTransactions} транзакций для тарифа "${planInfo.name}". Перейдите на тариф "PRO Личный" для снятия ограничений.`
          })
        }
      }
    }
    const { id, name, date, type, price, quantity, amount, category, category_id, comment, is_planned, planned_date, is_recurring, receipt_key, savings_type, goal_id } = req.body
    if (type === 'savings' && goal_id) {
      const { rows: goalRows } = await pool.query(
        'SELECT * FROM savings_goals WHERE id = $1 AND instance_id = $2',
        [goal_id, req.instanceId]
      )
      if (!goalRows.length) return res.status(404).json({ error: 'Цель не найдена' })
      const catId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
      const { rows } = await pool.query(
        `INSERT INTO transactions (id, name, date, type, price, quantity, amount, category_id, comment, instance_id, is_planned, planned_date, is_recurring, receipt_key, savings_type, goal_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'goal', $15) RETURNING *`,
        [id || crypto.randomUUID(), name, date, type, price, quantity, amount, catId, comment || '', req.instanceId, is_planned || false, planned_date || null, is_recurring || false, receipt_key || null, goal_id]
      )
      return res.status(201).json(rows[0])
    }
    const finalSavingsType = type === 'savings' ? (savings_type === 'goal' ? 'goal' : 'free') : null
    const finalGoalId = type === 'savings' ? (finalSavingsType === 'goal' ? goal_id : null) : null
    const finalCategoryName = type === 'savings' ? (finalSavingsType === 'goal' ? 'Цели' : 'Свободные накопления') : (category || '')
    const finalCategoryId = category_id || (finalCategoryName ? await resolveCategoryId(pool, req.instanceId, finalCategoryName, type || 'expense') : null)
    const { rows } = await pool.query(
      `INSERT INTO transactions (id, name, date, type, price, quantity, amount, category_id, comment, instance_id, is_planned, planned_date, is_recurring, receipt_key, savings_type, goal_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING *`,
      [id || crypto.randomUUID(), name, date, type || 'expense', price, quantity, amount, finalCategoryId, comment || '', req.instanceId, is_planned || false, planned_date || null, is_recurring || false, receipt_key || null, finalSavingsType, finalGoalId]
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


app.post('/api/instances/:instanceId/transactions/:id/execute', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE transactions SET is_planned = FALSE, date = CURRENT_DATE
       WHERE id = $1 AND instance_id = $2 AND is_planned = TRUE RETURNING *`,
      [req.params.id, req.instanceId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Запланированный расход не найден' })
    const executedTx = rows[0]

    // If it was marked as monthly recurring, schedule next month's planned transaction
    if (executedTx.is_recurring) {
      let nextDate = new Date()
      if (executedTx.planned_date) {
        const curD = new Date(executedTx.planned_date)
        if (!isNaN(curD.getTime())) nextDate = curD
      }
      nextDate.setMonth(nextDate.getMonth() + 1)
      const nextDateStr = nextDate.toISOString().slice(0, 10)

      await pool.query(
        `INSERT INTO transactions (id, name, date, type, price, quantity, amount, category_id, comment, instance_id, is_planned, planned_date, is_recurring)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, $11, TRUE)`,
        [
          crypto.randomUUID(), executedTx.name, nextDateStr, executedTx.type,
          executedTx.price, executedTx.quantity, executedTx.amount, executedTx.category_id,
          executedTx.comment, req.instanceId, nextDateStr
        ]
      )
    }

    res.json(executedTx)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


app.put('/api/instances/:instanceId/transactions/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, date, type, price, quantity, amount, category, category_id, comment, is_planned, planned_date, is_recurring } = req.body
    
    const { rows: txRows } = await pool.query('SELECT receipt_key FROM transactions WHERE id = $1 AND instance_id = $2', [req.params.id, req.instanceId])
    if (!txRows.length) return res.status(404).json({ error: 'Не найдено' })
    const rKey = txRows[0].receipt_key

    const finalCategoryId = category_id || (category ? await resolveCategoryId(pool, req.instanceId, category, type) : null)
    const { rows } = await pool.query(
      `UPDATE transactions SET name=$1, date=$2, type=$3, price=$4, quantity=$5, amount=$6, category_id=$7, comment=$8, is_planned=$9, planned_date=$10, is_recurring=$11
       WHERE id=$12 AND instance_id=$13 RETURNING *`,
      [name, date, type, price, quantity, amount, finalCategoryId, comment, is_planned || false, planned_date || null, is_recurring || false, req.params.id, req.instanceId]
    )

    
    if (rKey && rKey.startsWith('spend-goal-')) {
      await pool.query(
        `UPDATE transactions SET date=$1, amount=$2 
         WHERE receipt_key=$3 AND instance_id=$4 AND id != $5`,
        [date, amount, rKey, req.instanceId, req.params.id]
      )
    }

    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/transactions/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT receipt_key FROM transactions WHERE id = $1 AND instance_id = $2', [req.params.id, req.instanceId])
    if (!rows.length) return res.status(404).json({ error: 'Не найдено' })
    const rKey = rows[0].receipt_key
    let rowCount = 0
    if (rKey) {
      const resDel = await pool.query('DELETE FROM transactions WHERE receipt_key = $1 AND instance_id = $2', [rKey, req.instanceId])
      rowCount = resDel.rowCount
    }
    if (!rowCount) {
      const resDel = await pool.query('DELETE FROM transactions WHERE id = $1 AND instance_id = $2', [req.params.id, req.instanceId])
      rowCount = resDel.rowCount
    }
    if (!rowCount) return res.status(404).json({ error: 'Не найдено' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== SHOPPING LIST ROUTES (instance-scoped) ====================

app.get('/api/instances/:instanceId/shopping', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { all } = req.query
    let sql = 'SELECT id, name, bought, created_by, created_at FROM shopping_items WHERE instance_id = $1'
    const params = [req.instanceId]
    if (all !== 'true') {
      sql += ' AND bought = FALSE'
    }
    sql += ' ORDER BY bought ASC, created_at DESC'
    const { rows } = await pool.query(sql, params)
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/shopping', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name } = req.body
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Требуется название' })
    }
    const { rows } = await pool.query(
      'INSERT INTO shopping_items (name, instance_id, created_by) VALUES ($1, $2, $3) RETURNING id, name, bought, created_at',
      [name.trim(), req.instanceId, req.user.id]
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/instances/:instanceId/shopping/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, bought } = req.body
    const sets = []
    const params = []
    let idx = 1
    if (name !== undefined) {
      sets.push(`name = $${idx++}`)
      params.push(name.trim())
    }
    if (bought !== undefined) {
      sets.push(`bought = $${idx++}`)
      params.push(bought)
    }
    sets.push(`updated_at = NOW()`)
    if (!sets.length) return res.status(400).json({ error: 'Нечего обновлять' })
    params.push(req.params.id, req.instanceId)
    const { rows } = await pool.query(
      `UPDATE shopping_items SET ${sets.join(', ')} WHERE id = $${idx++} AND instance_id = $${idx++} RETURNING id, name, bought, updated_at`,
      params
    )
    if (!rows.length) return res.status(404).json({ error: 'Не найдено' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/shopping/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM shopping_items WHERE id = $1 AND instance_id = $2',
      [req.params.id, req.instanceId]
    )
    if (!rowCount) return res.status(404).json({ error: 'Не найдено' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== SAVINGS ROUTES ====================

app.get('/api/instances/:instanceId/savings', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { from, to } = req.query
    const conditions_t = ['t.instance_id = $1', "t.type = 'savings'"]
    const params_t = [req.instanceId]
    let i = 2
    if (from) { conditions_t.push(`t.date >= $${i++}`); params_t.push(from) }
    if (to) { conditions_t.push(`t.date <= $${i++}`); params_t.push(to) }
    const where_t = `WHERE ${conditions_t.join(' AND ')}`

      const { rows: goals } = await pool.query(
       `SELECT sg.*,
               COALESCE((SELECT SUM(t.amount) FROM transactions t
                         WHERE t.instance_id = sg.instance_id AND t.goal_id = sg.id AND t.type = 'savings' AND t.savings_type NOT IN ('withdrawal', 'adjustment')), 0) as saved
        FROM savings_goals sg
        WHERE sg.instance_id = $1
        ORDER BY sg.created_at DESC`,
       [req.instanceId]
      )

      const activeGoals = goals.filter(g => !g.is_completed)
      const completedGoals = goals.filter(g => g.is_completed)

      const { rows: transactions } = await pool.query(
       `SELECT t.*, c.name as category, sg.name as goal_name
        FROM transactions t
        LEFT JOIN categories c ON c.id = t.category_id
        LEFT JOIN savings_goals sg ON sg.id = t.goal_id
        ${where_t}
        ORDER BY t.date DESC, t.id DESC`,
       params_t
      )

       const { rows: byMonth } = await pool.query(
        `SELECT TO_CHAR(t.date, 'YYYY-MM') as month, SUM(t.amount) as total, COUNT(*) as count
         FROM transactions t ${where_t} AND t.savings_type != 'adjustment' GROUP BY month ORDER BY month ASC`,
        params_t
       )

      const { rows: freeSummary } = await pool.query(
       `SELECT SUM(t.amount) as total FROM transactions t ${where_t} AND t.savings_type = 'free'`,
       params_t
      )

      const { rows: totalSummary } = await pool.query(
       `SELECT SUM(t.amount) as total FROM transactions t ${where_t} AND t.savings_type NOT IN ('withdrawal', 'adjustment')`,
       params_t
      )

      const { rows: withdrawalSummary } = await pool.query(
       `SELECT SUM(t.amount) as total FROM transactions t ${where_t} AND t.savings_type = 'withdrawal'`,
       params_t
      )

      const { rows: adjustmentSummary } = await pool.query(
       `SELECT SUM(t.amount) as total FROM transactions t ${where_t} AND t.savings_type = 'adjustment'`,
       params_t
      )

      const { rows: withdrawals } = await pool.query(
       `SELECT t.*, c.name as category, sg.name as goal_name
        FROM transactions t
        LEFT JOIN categories c ON c.id = t.category_id
        LEFT JOIN savings_goals sg ON sg.id = t.goal_id
        ${where_t} AND t.savings_type = 'withdrawal'
        ORDER BY t.date DESC, t.id DESC`,
       params_t
      )

      const { rows: adjustments } = await pool.query(
       `SELECT t.*, c.name as category, sg.name as goal_name
        FROM transactions t
        LEFT JOIN categories c ON c.id = t.category_id
        LEFT JOIN savings_goals sg ON sg.id = t.goal_id
        ${where_t} AND t.savings_type = 'adjustment'
        ORDER BY t.date DESC, t.id DESC`,
       params_t
      )

      const freeTotal = parseFloat(freeSummary[0]?.total || 0)
      const totalSaved = parseFloat(totalSummary[0]?.total || 0)
      const withdrawalTotal = parseFloat(withdrawalSummary[0]?.total || 0)
      const adjustmentTotal = parseFloat(adjustmentSummary[0]?.total || 0)

      res.json({
       goals: activeGoals.map(g => ({ ...g, saved: parseFloat(g.saved), target_amount: parseFloat(g.target_amount), current_amount: parseFloat(g.saved) })),
       completedGoals: completedGoals.map(g => ({ ...g, saved: parseFloat(g.saved), target_amount: parseFloat(g.target_amount), current_amount: parseFloat(g.saved) })),
       transactions,
       byMonth: byMonth.map(r => ({ month: r.month, total: parseFloat(r.total), count: parseInt(r.count) })),
       freeTotal,
       totalSaved,
       withdrawalTotal,
       withdrawals,
       adjustmentTotal,
       adjustments
      })
   } catch (err) {
     res.status(500).json({ error: err.message })
   }
})

// Withdraw from savings
app.post('/api/instances/:instanceId/savings/withdraw', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { amount, goal_id, name, comment, date } = req.body
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Укажите сумму' })
    if (!name) return res.status(400).json({ error: 'Укажите название' })

    const withdrawAmount = parseFloat(amount)
    const targetDate = date || null

    if (goal_id) {
      const { rows: goalRows } = await pool.query(
        'SELECT * FROM savings_goals WHERE id = $1 AND instance_id = $2',
        [goal_id, req.instanceId]
      )
      if (!goalRows.length) return res.status(404).json({ error: 'Цель не найдена' })

      const { rows: savedRows } = await pool.query(
        "SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE instance_id = $1 AND goal_id = $2 AND type = 'savings' AND savings_type != 'withdrawal'",
        [req.instanceId, goal_id]
      )
      const savedTotal = parseFloat(savedRows[0].total)
      if (withdrawAmount > savedTotal) {
        return res.status(400).json({ error: 'Сумма изъятия превышает доступные накопления по цели' })
      }

      const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
      const catId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
      const { rows } = await pool.query(
        `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, goal_id, savings_type)
         VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, 'withdrawal')`,
        [newId, name, targetDate, withdrawAmount, catId, comment || '', req.instanceId, goal_id]
      )
      return res.status(201).json(rows[0])
    }

    // Free savings withdrawal
    const { rows: freeRows } = await pool.query(
      `SELECT SUM(t.amount) as total FROM transactions t
       WHERE t.instance_id = $1 AND t.type = 'savings' AND t.savings_type = 'free'`,
      [req.instanceId]
    )
    const freeTotal = parseFloat(freeRows[0]?.total || 0)
    if (withdrawAmount > freeTotal) {
      return res.status(400).json({ error: 'Сумма изъятия превышает свободные накопления' })
    }

    const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
    const catId = await resolveCategoryId(pool, req.instanceId, 'Свободные накопления', 'savings')
    const { rows } = await pool.query(
      `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, goal_id, savings_type)
       VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, $9)`,
      [newId, name, targetDate, withdrawAmount, catId, comment || '', req.instanceId, null, 'withdrawal']
    )
    res.status(201).json(rows[0])
   } catch (err) {
     res.status(500).json({ error: err.message })
   }
})

// Adjust savings (make a minus/reduce)
app.post('/api/instances/:instanceId/savings/adjust', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { amount, goal_id, name, comment, date } = req.body
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Укажите сумму' })
    if (!name) return res.status(400).json({ error: 'Укажите название' })

    const adjustAmount = parseFloat(amount)
    const targetDate = date || null

    if (goal_id) {
      const { rows: goalRows } = await pool.query(
        'SELECT * FROM savings_goals WHERE id = $1 AND instance_id = $2',
        [goal_id, req.instanceId]
      )
      if (!goalRows.length) return res.status(404).json({ error: 'Цель не найдена' })

      const { rows: savedRows } = await pool.query(
        "SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE instance_id = $1 AND goal_id = $2 AND type = 'savings' AND savings_type NOT IN ('withdrawal', 'adjustment')",
        [req.instanceId, goal_id]
      )
      const savedTotal = parseFloat(savedRows[0].total)
      if (adjustAmount > savedTotal) {
        return res.status(400).json({ error: 'Сумма корректировки превышает доступные накопления по цели' })
      }

      const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
      const catId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
      const { rows } = await pool.query(
        `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, goal_id, savings_type)
         VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, 'adjustment')`,
        [newId, name, targetDate, adjustAmount, catId, comment || '', req.instanceId, goal_id]
      )
      return res.status(201).json(rows[0])
    }

    // Free savings adjustment
    const { rows: freeRows } = await pool.query(
      `SELECT SUM(t.amount) as total FROM transactions t
       WHERE t.instance_id = $1 AND t.type = 'savings' AND t.savings_type = 'free'`,
      [req.instanceId]
    )
    const freeTotal = parseFloat(freeRows[0]?.total || 0)
    if (adjustAmount > freeTotal) {
      return res.status(400).json({ error: 'Сумма корректировки превышает свободные накопления' })
    }

    const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
    const catId = await resolveCategoryId(pool, req.instanceId, 'Свободные накопления', 'savings')
    const { rows } = await pool.query(
      `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, goal_id, savings_type)
       VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, $9)`,
      [newId, name, targetDate, adjustAmount, catId, comment || '', req.instanceId, null, 'adjustment']
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Partially assign free savings to a goal
app.post('/api/instances/:instanceId/savings/assign-partial', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { assignments, goal_id } = req.body
    if (!assignments || !assignments.length || !goal_id) {
      return res.status(400).json({ error: 'Требуется передать assignments и goal_id' })
    }

    for (const a of assignments) {
      if (!a.tx_id || !a.amount || a.amount <= 0) continue

      // Get original transaction
      const { rows: orig } = await pool.query(
        "SELECT * FROM transactions WHERE id = $1 AND instance_id = $2 AND type = 'savings' AND (savings_type = 'free' OR savings_type IS NULL) AND savings_type != 'adjustment'",
        [String(a.tx_id), req.instanceId]
      )
      if (!orig.length) continue
      const tx = orig[0]

      const assignAmount = parseFloat(a.amount)
      const currentAmount = parseFloat(tx.amount)
      if (assignAmount > currentAmount) {
        return res.status(400).json({ error: 'Сумма распределения превышает сумму транзакции для tx ' + a.tx_id })
      }

      if (assignAmount === currentAmount) {
        // Full amount — just update the original
        const catId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
        await pool.query(
          "UPDATE transactions SET goal_id = $1, savings_type = 'goal', category_id = $2 WHERE id = $3",
          [goal_id, catId, String(a.tx_id)]
        )
      } else {
        // Partial — create new goal tx, reduce original
        const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
        const catId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
        await pool.query(
          `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, goal_id, savings_type)
           VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, 'goal')`,
          [newId, tx.name + ' (часть)', tx.date, assignAmount, catId, tx.comment || '', req.instanceId, goal_id]
        )
        await pool.query(
          'UPDATE transactions SET amount = amount - $1 WHERE id = $2',
          [assignAmount, a.tx_id]
        )
      }
    }

    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Assign a single amount from the free savings pool to a goal
app.post('/api/instances/:instanceId/savings/assign', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { amount, goal_id } = req.body
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Укажите сумму' })
    if (!goal_id) return res.status(400).json({ error: 'Укажите цель' })

    const { rows: goalRows } = await pool.query(
      'SELECT * FROM savings_goals WHERE id = $1 AND instance_id = $2',
      [goal_id, req.instanceId]
    )
    if (!goalRows.length) return res.status(404).json({ error: 'Цель не найдена' })

    const assignAmount = parseFloat(amount)

    const { rows: freeRows } = await pool.query(
      `SELECT SUM(t.amount) as total FROM transactions t
       WHERE t.instance_id = $1 AND t.type = 'savings' AND (t.savings_type = 'free' OR t.savings_type IS NULL)`,
      [req.instanceId]
    )
    const freeTotal = parseFloat(freeRows[0]?.total || 0)
    if (assignAmount > freeTotal) {
      return res.status(400).json({ error: 'Сумма превышает свободные накопления' })
    }

    const { rows: freeTx } = await pool.query(
      `SELECT * FROM transactions t
       WHERE t.instance_id = $1 AND t.type = 'savings' AND (t.savings_type = 'free' OR t.savings_type IS NULL)
       ORDER BY t.date ASC, t.id ASC`,
      [req.instanceId]
    )

    let remaining = assignAmount
    for (const tx of freeTx) {
      if (remaining <= 0) break
      const currentAmount = parseFloat(tx.amount)
      if (currentAmount <= 0) continue

      if (remaining >= currentAmount) {
        const catId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
        await pool.query(
          "UPDATE transactions SET goal_id = $1, savings_type = 'goal', category_id = $2 WHERE id = $3",
          [goal_id, catId, tx.id]
        )
        remaining = +(remaining - currentAmount).toFixed(2)
      } else {
        const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
        const catId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
        await pool.query(
          `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, goal_id, savings_type)
           VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, 'goal')`,
          [newId, tx.name + ' (часть)', tx.date, remaining, catId, tx.comment || '', req.instanceId, goal_id]
        )
        await pool.query(
          'UPDATE transactions SET amount = amount - $1 WHERE id = $2',
          [remaining, tx.id]
        )
        remaining = 0
      }
    }

    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Transfer savings between goals or to free
app.post('/api/instances/:instanceId/savings/transfer', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { from_goal_id, to_goal_id, to: toTarget, amount } = req.body
    if (!from_goal_id || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Требуется передать from_goal_id и amount' })
    }
    if (toTarget !== 'free' && !to_goal_id) {
      return res.status(400).json({ error: 'Требуется указать место назначения' })
    }

    // Get source goal
    const { rows: goalRows } = await pool.query(
      'SELECT * FROM savings_goals WHERE id = $1 AND instance_id = $2',
      [from_goal_id, req.instanceId]
    )
    if (!goalRows.length) return res.status(404).json({ error: 'Цель не найдена' })
    const goal = goalRows[0]

     // Calculate current saved amount (excluding withdrawals and adjustments)
     const { rows: savedRows } = await pool.query(
       "SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE instance_id = $1 AND goal_id = $2 AND type = 'savings' AND savings_type NOT IN ('withdrawal', 'adjustment')",
       [req.instanceId, from_goal_id]
     )
     const savedTotal = parseFloat(savedRows[0].total)
     if (amount > savedTotal) {
       return res.status(400).json({ error: 'Сумма превышает накопленный итог' })
     }

     // Get transactions for this goal (most recent first to partially move), exclude withdrawals and adjustments
     const { rows: txRows } = await pool.query(
       "SELECT * FROM transactions WHERE instance_id = $1 AND goal_id = $2 AND type = 'savings' AND savings_type NOT IN ('withdrawal', 'adjustment') ORDER BY date DESC, id DESC",
       [req.instanceId, from_goal_id]
     )

    let remaining = parseFloat(amount)
    for (const tx of txRows) {
      if (remaining <= 0) break
      const txAmount = parseFloat(tx.amount)
      const moveAmount = Math.min(txAmount, remaining)

       if (moveAmount === txAmount) {
        // Full transaction — just update goal_id
        if (toTarget === 'free') {
          const catId = await resolveCategoryId(pool, req.instanceId, 'Свободные накопления', 'savings')
          await pool.query("UPDATE transactions SET goal_id = NULL, savings_type = 'free', category_id = $1 WHERE id = $2", [catId, tx.id])
        } else {
          const catId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
          await pool.query("UPDATE transactions SET goal_id = $1, savings_type = 'goal', category_id = $2 WHERE id = $3", [to_goal_id, catId, tx.id])
        }
      } else {
        // Partial — create new tx, reduce original
        const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
        const newSavingsType = toTarget === 'free' ? 'free' : 'goal'
        const newGoalId = toTarget === 'free' ? null : to_goal_id
        const newCategoryName = toTarget === 'free' ? 'Свободные накопления' : 'Цели'
        const catId = await resolveCategoryId(pool, req.instanceId, newCategoryName, 'savings')
        await pool.query(
          "INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, goal_id, savings_type) VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, $9)",
          [newId, tx.name + ' (перевод)', tx.date, moveAmount, catId, tx.comment || '', req.instanceId, newGoalId, newSavingsType]
        )
        await pool.query('UPDATE transactions SET amount = amount - $1 WHERE id = $2', [moveAmount, tx.id])
      }
      remaining -= moveAmount
    }

    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Spend directly from goal (creates withdrawal + expense)
app.post('/api/instances/:instanceId/savings/spend-from-goal', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { goal_id, amount, date, name, comment, mark_completed } = req.body
    if (!goal_id || !amount || parseFloat(amount) <= 0) {
      return res.status(400).json({ error: 'Неверные данные' })
    }
    const spendAmount = parseFloat(amount)
    const txDate = date || new Date().toISOString()
    
    // Get goal info
    const { rows: goalRows } = await pool.query('SELECT * FROM savings_goals WHERE id = $1 AND instance_id = $2', [goal_id, req.instanceId])
    if (!goalRows.length) return res.status(404).json({ error: 'Цель не найдена' })
    const goal = goalRows[0]
    
    const txName = name || goal.name
    const txComment = comment || 'Потрачено из цели'

    const rKey = 'spend-goal-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)

    // 1. Withdraw from goal
    const wId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
    const savCatId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'savings')
    await pool.query(
      `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, goal_id, savings_type, receipt_key)
       VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, 'withdrawal', $9)`,
      [wId, 'Изъятие на покупку: ' + goal.name, txDate, spendAmount, savCatId, '', req.instanceId, goal_id, rKey]
    )

    // 2. Create expense
    const eId = 'exp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
    const expCatId = await resolveCategoryId(pool, req.instanceId, 'Цели', 'expense')
    await pool.query(
      `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id, receipt_key)
       VALUES ($1, $2, $3, 'expense', $4, $5, $6, $7, $8)`,
      [eId, txName, txDate, spendAmount, expCatId, txComment, req.instanceId, rKey]
    )

    // 3. Mark goal as completed if requested
    if (mark_completed) {
      await pool.query(
        `UPDATE savings_goals SET is_completed = TRUE, completed_at = NOW() WHERE id = $1 AND instance_id = $2`,
        [goal_id, req.instanceId]
      )
    }

    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Complete a savings goal directly
app.post('/api/instances/:instanceId/savings/:id/complete', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const goalId = req.params.id
    const { rows: goalRows } = await pool.query('SELECT * FROM savings_goals WHERE id = $1 AND instance_id = $2', [goalId, req.instanceId])
    if (!goalRows.length) return res.status(404).json({ error: 'Цель не найдена' })

    await pool.query(
      `UPDATE savings_goals SET is_completed = TRUE, completed_at = NOW() WHERE id = $1 AND instance_id = $2`,
      [goalId, req.instanceId]
    )
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


app.post('/api/instances/:instanceId/savings', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, target_amount, target_date, comment } = req.body
    if (!name || !target_amount) return res.status(400).json({ error: 'Требуется название и целевая сумма' })
    const { rows } = await pool.query(
      `INSERT INTO savings_goals (name, target_amount, instance_id, target_date, comment)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, target_amount, req.instanceId, target_date || null, comment || '']
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/instances/:instanceId/savings/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, target_amount, target_date, comment, current_amount } = req.body
    const { rows } = await pool.query(
      `UPDATE savings_goals SET name=$1, target_amount=$2, target_date=$3, comment=$4, current_amount=$5
       WHERE id=$6 AND instance_id=$7 RETURNING *`,
      [name, target_amount, target_date || null, comment || '', current_amount || 0, req.params.id, req.instanceId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Не найдено' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/savings/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const { rowCount } = await client.query(
      'DELETE FROM savings_goals WHERE id = $1 AND instance_id = $2',
      [req.params.id, req.instanceId]
    )
    if (!rowCount) {
      await client.query('ROLLBACK')
      return res.status(404).json({ error: 'Не найдено' })
    }
    await client.query(
      "UPDATE transactions SET goal_id = NULL, savings_type = 'free' WHERE instance_id = $1 AND goal_id = $2 AND savings_type = 'goal'",
      [req.instanceId, req.params.id]
    )
    await client.query(
      'UPDATE transactions SET goal_id = NULL WHERE instance_id = $1 AND goal_id = $2 AND savings_type != $3',
      [req.instanceId, req.params.id, 'goal']
    )
    await client.query('COMMIT')
    res.json({ ok: true })
  } catch (err) {
    await client.query('ROLLBACK')
    res.status(500).json({ error: err.message })
  } finally {
    client.release()
  }
})

// ==================== CREDITS ROUTES ====================

app.get('/api/instances/:instanceId/credits', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.*,
              COALESCE((SELECT SUM(cp.amount) FROM credit_payments cp WHERE cp.credit_id = c.id), 0) as total_paid,
              COALESCE((SELECT SUM(cp.principal_amount) FROM credit_payments cp WHERE cp.credit_id = c.id), 0) as total_principal,
              COALESCE((SELECT SUM(cp.interest_amount) FROM credit_payments cp WHERE cp.credit_id = c.id), 0) as total_interest,
              (SELECT COUNT(*) FROM credit_payments cp WHERE cp.credit_id = c.id) as payment_count
       FROM credits c
       WHERE c.instance_id = $1
       ORDER BY c.created_at DESC`,
      [req.instanceId]
    )
    res.json(rows.map(r => ({
      ...r,
      total_amount: parseFloat(r.total_amount),
      interest_rate: parseFloat(r.interest_rate),
      monthly_payment: parseFloat(r.monthly_payment),
      remaining_amount: parseFloat(r.remaining_amount != null ? r.remaining_amount : r.total_amount),
      total_paid: parseFloat(r.total_paid),
      total_principal: parseFloat(r.total_principal),
      total_interest: parseFloat(r.total_interest),
      payment_count: parseInt(r.payment_count)
    })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/credits', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, lender, total_amount, interest_rate, monthly_payment, payment_day, start_date, end_date, comment } = req.body
    if (!name || !total_amount) return res.status(400).json({ error: 'Name and total amount required' })
    const remaining = total_amount
    const { rows } = await pool.query(
      `INSERT INTO credits (name, instance_id, lender, total_amount, interest_rate, monthly_payment, payment_day, start_date, end_date, remaining_amount, comment)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [name, req.instanceId, lender || '', parseFloat(total_amount), parseFloat(interest_rate) || 0, parseFloat(monthly_payment) || 0, payment_day ? parseInt(payment_day) : null, start_date || null, end_date || null, remaining, comment || '']
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/instances/:instanceId/credits/:creditId', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, lender, total_amount, interest_rate, monthly_payment, payment_day, start_date, end_date, comment } = req.body
    if (!name) return res.status(400).json({ error: 'Name required' })
    const { rows } = await pool.query(
      `UPDATE credits SET name=$1, lender=$2, total_amount=$3, interest_rate=$4, monthly_payment=$5, payment_day=$6, start_date=$7, end_date=$8, comment=$9
       WHERE id=$10 AND instance_id=$11 RETURNING *`,
      [name, lender || '', parseFloat(total_amount) || 0, parseFloat(interest_rate) || 0, parseFloat(monthly_payment) || 0, payment_day ? parseInt(payment_day) : null, start_date || null, end_date || null, comment || '', req.params.creditId, req.instanceId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Credit not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/credits/:creditId', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM credits WHERE id = $1 AND instance_id = $2', [req.params.creditId, req.instanceId])
    if (!rowCount) return res.status(404).json({ error: 'Credit not found' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/instances/:instanceId/credits/:creditId/payments', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT cp.*, c.name as credit_name
       FROM credit_payments cp
       JOIN credits c ON c.id = cp.credit_id
       WHERE cp.credit_id = $1
       ORDER BY cp.payment_date DESC, cp.id DESC`,
      [req.params.creditId]
    )
  res.json(rows.map(r => ({
    ...r,
    amount: parseFloat(r.amount),
    principal_amount: parseFloat(r.principal_amount),
    interest_amount: parseFloat(r.interest_amount)
  })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/instances/:instanceId/credit-payments', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT cp.*, c.name as credit_name
       FROM credit_payments cp
       JOIN credits c ON c.id = cp.credit_id
       WHERE c.instance_id = $1
       ORDER BY cp.payment_date DESC, cp.id DESC
       LIMIT 200`,
      [req.instanceId]
    )
    res.json(rows.map(r => ({
      ...r,
      amount: parseFloat(r.amount),
      principal_amount: parseFloat(r.principal_amount),
      interest_amount: parseFloat(r.interest_amount)
    })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/instances/:instanceId/credits/:creditId/calculate-early', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { amount, strategy, payment_date } = req.query
    const earlyAmount = parseFloat(amount)
    const payDate = payment_date || new Date().toISOString().slice(0, 10)
    if (!earlyAmount || earlyAmount <= 0) return res.status(400).json({ error: 'Valid amount required' })
    if (!strategy || !['reduce_term', 'reduce_payment'].includes(strategy)) {
      return res.status(400).json({ error: 'Strategy must be reduce_term or reduce_payment' })
    }

    const { rows: creditRows } = await pool.query('SELECT * FROM credits WHERE id = $1 AND instance_id = $2', [req.params.creditId, req.instanceId])
    if (!creditRows.length) return res.status(404).json({ error: 'Credit not found' })
    const credit = creditRows[0]

    const remaining = parseFloat(credit.remaining_amount != null ? credit.remaining_amount : credit.total_amount)
    const monthlyRate = parseFloat(credit.interest_rate) / 100 / 12
    const currentMonthly = parseFloat(credit.monthly_payment)

    if (earlyAmount >= remaining) {
      return res.json({
        current_remaining: remaining,
        early_amount: earlyAmount,
        new_remaining: 0,
        months_saved: Infinity,
        new_monthly_payment: 0,
        overpayment: earlyAmount - remaining,
        is_fully_paid: true
      })
    }

    const newRemaining = remaining - earlyAmount

    if (strategy === 'reduce_term' && currentMonthly > 0 && monthlyRate > 0) {
      const monthsLeft = Math.ceil(Math.log(currentMonthly / (currentMonthly - newRemaining * monthlyRate)) / Math.log(1 + monthlyRate))
      const origMonthsLeft = Math.ceil(Math.log(currentMonthly / (currentMonthly - remaining * monthlyRate)) / Math.log(1 + monthlyRate))
      const monthsSaved = Math.max(origMonthsLeft - monthsLeft, 0)
      const origTotal = currentMonthly * origMonthsLeft
      const newTotal = currentMonthly * monthsLeft + earlyAmount
      const interestSaved = Math.max(origTotal - remaining - (newTotal - newRemaining), 0)
      res.json({
        current_remaining: remaining, early_amount: earlyAmount, new_remaining: newRemaining,
        strategy: 'reduce_term', months_saved: monthsSaved,
        new_monthly_payment: currentMonthly, original_months_left: origMonthsLeft,
        new_months_left: monthsLeft, interest_saved: Math.max(interestSaved, 0),
        is_fully_paid: false, overpayment: 0
      })
    } else if (strategy === 'reduce_term') {
      const monthsPaidOff = Math.floor(earlyAmount / currentMonthly)
      res.json({
        current_remaining: remaining, early_amount: earlyAmount, new_remaining: newRemaining,
        strategy: 'reduce_term', months_saved: monthsPaidOff,
        new_monthly_payment: currentMonthly, is_fully_paid: false, overpayment: 0
      })
    } else {
      if (currentMonthly > 0 && monthlyRate > 0) {
        const { rows: paidRows } = await pool.query(
          "SELECT COUNT(*) as cnt FROM credit_payments WHERE credit_id = $1 AND payment_type = 'regular'",
          [req.params.creditId]
        )
        const monthsPaid = parseInt(paidRows[0].cnt)
        const origEnd = credit.end_date ? new Date(credit.end_date) : null
        const startDate = credit.start_date ? new Date(credit.start_date) : new Date()
        const totalMonthsOrig = origEnd ? Math.round((origEnd - startDate) / (1000 * 60 * 60 * 24 * 30.44)) : monthsPaid + Math.ceil(remaining / currentMonthly)
        const remainingMonthsNew = totalMonthsOrig - monthsPaid
        const newMonthly = remainingMonthsNew > 0 ? newRemaining / remainingMonthsNew : 0
        const reduction = currentMonthly - newMonthly
        res.json({
          current_remaining: remaining, early_amount: earlyAmount, new_remaining: newRemaining,
          strategy: 'reduce_payment', new_monthly_payment: Math.max(newMonthly, 0),
          payment_reduction: Math.max(reduction, 0), is_fully_paid: false, overpayment: 0
        })
      } else {
        const monthsLeft = Math.ceil(newRemaining / currentMonthly) || 0
        res.json({
          current_remaining: remaining, early_amount: earlyAmount, new_remaining: newRemaining,
          strategy: 'reduce_payment', new_monthly_payment: monthsLeft > 0 ? newRemaining / monthsLeft : 0,
          payment_reduction: 0, is_fully_paid: false, overpayment: 0
        })
      }
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/credits/:creditId/payments', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { amount, principal_amount, interest_amount, payment_date, comment, create_transaction, payment_type, early_strategy } = req.body
    if (!amount || !payment_date) return res.status(400).json({ error: 'Amount and payment date required' })
    const isEarly = payment_type === 'early'

    const parseDateInput = (val) => {
      if (!val) return new Date().toISOString().slice(0, 10)
      if (typeof val === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(val)) return val
      const months = { 'янв': '01', 'фев': '02', 'мар': '03', 'апр': '04', 'май': '05', 'мая': '05', 'июн': '06', 'июл': '07', 'авг': '08', 'сен': '09', 'окт': '10', 'ноя': '11', 'дек': '12' }
      const match = typeof val === 'string' && val.match(/^(\d{1,2})\s+([а-яА-Яa-zA-Z]+)\s+(\d{4})/)
      if (match) {
        const day = match[1].padStart(2, '0')
        const monKey = match[2].toLowerCase().slice(0, 3)
        const month = months[monKey] || '01'
        return `${match[3]}-${month}-${day}`
      }
      const d = new Date(val)
      return isNaN(d.getTime()) ? new Date().toISOString().slice(0, 10) : d.toISOString().slice(0, 10)
    }
    const normDate = parseDateInput(payment_date)

    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      const principal = parseFloat(principal_amount) || 0
      const interest = parseFloat(interest_amount) || 0

      const { rows } = await client.query(
        `INSERT INTO credit_payments (credit_id, amount, principal_amount, interest_amount, payment_date, comment, payment_type, early_strategy)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
        [req.params.creditId, parseFloat(amount), principal, interest, normDate, comment || '', isEarly ? 'early' : 'regular', isEarly ? (early_strategy || 'reduce_term') : null]
      )

      await client.query(
        'UPDATE credits SET remaining_amount = GREATEST(COALESCE(remaining_amount, total_amount) - $1, 0) WHERE id = $2',
        [principal || parseFloat(amount), req.params.creditId]
      )

      if (create_transaction) {
        const { rows: creditRows } = await client.query('SELECT name FROM credits WHERE id = $1', [req.params.creditId])
        const creditName = creditRows[0]?.name || 'Кредит'
        const txId = 'tx-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
        const catId = await resolveCategoryId(client, req.instanceId, 'кредиты', 'expense')
        await client.query(
          `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id)
           VALUES ($1, $2, $3, 'expense', $4, $5, $6, $7)`,
          [txId, 'Платёж по кредиту: ' + creditName, normDate, parseFloat(amount), catId, `Основной долг: ${principal.toFixed(2)}, Проценты: ${interest.toFixed(2)}`, req.instanceId]
        )
      }

      await client.query('COMMIT')
      res.status(201).json(rows[0])
    } catch (err) {
      await client.query('ROLLBACK')
      throw err
    } finally {
      client.release()
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/credits/:creditId/payments/:paymentId', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows: paymentRows } = await pool.query(
      'DELETE FROM credit_payments WHERE id = $1 AND credit_id = $2 RETURNING *',
      [req.params.paymentId, req.params.creditId]
    )
    if (!paymentRows.length) return res.status(404).json({ error: 'Payment not found' })
    const payment = paymentRows[0]
    await pool.query(
      'UPDATE credits SET remaining_amount = remaining_amount + $1 WHERE id = $2',
      [parseFloat(payment.principal_amount) || parseFloat(payment.amount), req.params.creditId]
    )
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== CATEGORIES (instance-scoped) ====================

app.post('/api/instances/:instanceId/categories', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim()
    const type = String(req.body.type || '').trim()
    if (!name) return res.status(400).json({ error: 'Укажите название' })
    if (SERVICE_CATEGORY_NAMES.has(name)) return res.status(400).json({ error: 'Служебная категория' })
    if (!['expense', 'income', 'savings'].includes(type)) return res.status(400).json({ error: 'Неверный тип категории' })
    const { rows: dup } = await pool.query(
      'SELECT id FROM categories WHERE instance_id = $1 AND name = $2', [req.instanceId, name]
    )
    if (dup.length) return res.status(400).json({ error: 'Категория с таким названием уже существует' })
    const { rows } = await pool.query(
      'INSERT INTO categories (name, type, instance_id, is_default) VALUES ($1, $2, $3, FALSE) RETURNING *',
      [name, type, req.instanceId]
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/instances/:instanceId/categories', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT DISTINCT ON (c.name) c.id, c.name, c.type, c.is_default, c.instance_id IS NOT NULL AS is_instance,
              (SELECT COUNT(*) FROM transactions t WHERE t.instance_id = $1 AND t.category_id = c.id) AS used
       FROM categories c
       WHERE (c.instance_id IS NULL OR c.instance_id = $1)
         AND NOT EXISTS (
           SELECT 1 FROM category_hidden h
           WHERE h.instance_id = $1 AND h.category_id = c.id
         )
       ORDER BY c.name, (c.instance_id = $1) DESC NULLS LAST`,
      [req.instanceId]
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/instances/:instanceId/categories/:categoryId', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    const { name } = req.body
    const newName = String(name || '').trim()
    if (!newName) return res.status(400).json({ error: 'Укажите название' })
    if (SERVICE_CATEGORY_NAMES.has(newName)) return res.status(400).json({ error: 'Служебная категория, переименование запрещено' })

    const { rows: catRows } = await pool.query('SELECT * FROM categories WHERE id = $1', [req.params.categoryId])
    if (!catRows.length) return res.status(404).json({ error: 'Категория не найдена' })
    const cat = catRows[0]
    if (SERVICE_CATEGORY_NAMES.has(cat.name)) return res.status(400).json({ error: 'Служебная категория, переименование запрещено' })
    if (cat.name === newName) return res.json(cat)

    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      let targetId = cat.id
      if (cat.instance_id !== req.instanceId) {
        // Global template — materialize an instance copy with the new name and repoint this instance's txs
        const cp = await client.query(
          'SELECT id FROM categories WHERE instance_id = $1 AND name = $2', [req.instanceId, newName]
        )
        if (cp.rows.length) {
          targetId = cp.rows[0].id
          await client.query(
            'UPDATE transactions SET category_id = $1 WHERE instance_id = $2 AND category_id = $3',
            [targetId, req.instanceId, cat.id]
          )
        } else {
          const ins = await client.query(
            'INSERT INTO categories (name, type, instance_id, is_default) VALUES ($1, $2, $3, FALSE) RETURNING id',
            [newName, cat.type, req.instanceId]
          )
          targetId = ins.rows[0].id
          await client.query(
            'UPDATE transactions SET category_id = $1 WHERE instance_id = $2 AND category_id = $3',
            [targetId, req.instanceId, cat.id]
          )
        }
        await client.query(
          'INSERT INTO category_hidden (instance_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [req.instanceId, cat.id]
        )
      } else {
        const dup = await client.query(
          'SELECT id FROM categories WHERE instance_id = $1 AND name = $2 AND id != $3',
          [req.instanceId, newName, cat.id]
        )
        if (dup.rows.length) {
          await client.query('ROLLBACK')
          return res.status(400).json({ error: 'Категория с таким названием уже существует' })
        }
        await client.query('UPDATE categories SET name = $1 WHERE id = $2', [newName, cat.id])
        targetId = cat.id
        const gl = await client.query(
          'SELECT id FROM categories WHERE instance_id IS NULL AND name = $1', [cat.name]
        )
        if (gl.rows.length) {
          await client.query(
            'INSERT INTO category_hidden (instance_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [req.instanceId, gl.rows[0].id]
          )
        }
      }
      await client.query('COMMIT')
      const { rows } = await pool.query('SELECT * FROM categories WHERE id = $1', [targetId])
      res.json(rows[0])
    } catch (err) {
      await client.query('ROLLBACK')
      throw err
    } finally {
      client.release()
    }
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Категория с таким названием уже существует' })
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/categories/:categoryId', authMiddleware, instanceMiddleware, instanceOwnerMiddleware, async (req, res) => {
  try {
    const { replace_category_id, new_category_name } = req.body || {}
    const { rows: catRows } = await pool.query('SELECT * FROM categories WHERE id = $1', [req.params.categoryId])
    if (!catRows.length) return res.status(404).json({ error: 'Категория не найдена' })
    const cat = catRows[0]
    if (SERVICE_CATEGORY_NAMES.has(cat.name)) return res.status(400).json({ error: 'Служебная категория, удаление запрещено' })

    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      if (cat.instance_id !== req.instanceId) {
        // Global template — hide it for this instance only
        await client.query(
          'INSERT INTO category_hidden (instance_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [req.instanceId, cat.id]
        )
        await client.query('COMMIT')
        return res.json({ ok: true, hidden: true })
      }

      const { rows: cnt } = await client.query(
        'SELECT COUNT(*)::int AS n FROM transactions WHERE instance_id = $1 AND category_id = $2',
        [req.instanceId, cat.id]
      )
      const used = cnt[0].n

      if (used > 0) {
        let replaceId = parseInt(replace_category_id, 10)
        if (!replaceId && new_category_name) {
          const resolved = await resolveCategoryId(client, req.instanceId, String(new_category_name).trim(), cat.type)
          replaceId = resolved
        }
        if (!replaceId) {
          await client.query('ROLLBACK')
          return res.status(400).json({ error: 'Категория используется', used, message: 'Укажите категорию для переноса транзакций' })
        }
        if (replaceId === cat.id) {
          await client.query('ROLLBACK')
          return res.status(400).json({ error: 'Нельзя переносить на удаляемую категорию' })
        }
        await client.query(
          'UPDATE transactions SET category_id = $1 WHERE instance_id = $2 AND category_id = $3',
          [replaceId, req.instanceId, cat.id]
        )
      }

      await client.query('DELETE FROM categories WHERE id = $1', [cat.id])
      await client.query(
        'DELETE FROM category_hidden WHERE instance_id = $1 AND category_id = (SELECT id FROM categories WHERE instance_id IS NULL AND name = $2)',
        [req.instanceId, cat.name]
      )
      await client.query('COMMIT')
      res.json({ ok: true, deleted: true })
    } catch (err) {
      await client.query('ROLLBACK')
      throw err
    } finally {
      client.release()
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== SUMMARY (instance-scoped) ====================

app.get('/api/instances/:instanceId/summary', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { from, to, category_id } = req.query
    const conditions = ['t.instance_id = $1']
    const params = [req.instanceId]
    let i = 2
    if (from) { conditions.push(`t.date >= $${i++}`); params.push(from) }
    if (to) { conditions.push(`t.date <= $${i++}`); params.push(to) }
    if (category_id) { conditions.push(`t.category_id = $${i++}`); params.push(category_id) }
    const where = `WHERE ${conditions.join(' AND ')}`
    const { rows } = await pool.query(
      `SELECT TO_CHAR(t.date, 'YYYY-MM') as month, c.name as category, COUNT(*) as count, SUM(t.amount) as total
       FROM transactions t LEFT JOIN categories c ON c.id = t.category_id ${where}
       GROUP BY month, c.name ORDER BY month DESC, total DESC`,
      params
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== SUGGEST CATEGORY (instance-scoped) ====================

const CATEGORY_KEYWORDS = [
  [/(^|[^а-яa-z0-9])(молок[оае]|хлеб[а]?|мяс[оа]|сыр[а]?|колбас[аы]|масл[оа]|яйц[ао]|сметан[а]?|йогурт|творог|кефир|овощ[и]?|фрукт[ы]?|картоф[еь]|лук[а]?|морков[ьи]|капуст[а]?|сок[а]?|вод[аы]|сосиск[иа]|кетчуп|майонез|соль|сахар|мук[аи]|кру[па]{2}|рис[а]?|макарон|гречк|овсян)($|[^а-яa-z0-9])/i, 'продукты'],
  [/(^|[^а-яa-z0-9])(коммунал|жку|газ[а]?|свет|электр[о]?|отоплен|квартплат)($|[^а-яa-z0-9])/i, 'ЖКУ'],
  [/(^|[^а-яa-z0-9])(бензин|автомоб[или]?|шин[аы]|запчаст[и]?|топлив[оа]|дизел[ь]?|гараж|стоянк|парковк|мойк[аи]|техосмотр)($|[^а-яa-z0-9])/i, 'автомобиль'],
  [/(^|[^а-яa-z0-9])(лекарств[оа]|аптек[аи]|таблетк[иа]|витамин[ы]?|врач[а]?|больниц[аы]|поликлиник|медицин|анализ[ы]?)($|[^а-яa-z0-9])/i, 'здоровье'],
  [/(^|[^а-яa-z0-9])(сладост[и]?|конфет[ыа]|шоколад|пирожн[ое]|торт[а]?|морожен[оа]|десерт[а]?|леденец|карамел[ь]?|пряник[и]?|вафл[и]?)($|[^а-яa-z0-9])/i, 'сладости'],
  [/(^|[^а-яa-z0-9])(развлеч|кино|театр|концерт|парк[а]?|аттракцион|квест|игр[ау]|боулинг|бильярд)($|[^а-яa-z0-9])/i, 'развлечения'],
  [/(^|[^а-яa-z0-9])(связ[ьи]|телефон|интернет|мобильн|сим-карт|тариф)($|[^а-яa-z0-9])/i, 'связь'],
  [/(^|[^а-яa-z0-9])(подар[о]?[к]?[а-я]{0,4}|сувенир|праздник[а]?|день\s*рождени|открытк[аи]|цвет[ыа])($|[^а-яa-z0-9])/i, 'подарки'],
  [/(^|[^а-яa-z0-9])(одежд[аы]|обув[ьи]|куртк[аи]|пальт[оа]|джинс[ы]?|футболк[аи]|рубашк[аи]|плать[ея]|кроссовк[иа]|сапог[и]?|брюк[и]?)($|[^а-яa-z0-9])/i, 'одежда'],
  [/(^|[^а-яa-z0-9])(питом[е]?[ц]?|собак[аи]|кошк[аи]|корм[а]?|ветеринар|зоомагазин)($|[^а-яa-z0-9])/i, 'питомцы'],
  [/(^|[^а-яa-z0-9])(огород|рассад[аы]|семен[а]?|сажен[еццы]|лопат[аы]|удобрени|теплиц[аы])($|[^а-яa-z0-9])/i, 'огород'],
  [/(^|[^а-яa-z0-9])(готовая\s*еда|обед[а]?|ужин[а]?|завтрак[а]?|суп[а]?|салат[а]?|курьер|доставк[аи]|ресторан|столов[ая]й|каф[е]?|шаурм[а]?|бургер|пицц[аы]|ролл[ы]?|суши)($|[^а-яa-z0-9])/i, 'готовая еда'],
  [/(^|[^а-яa-z0-9])(благотворительн|пожертв|помощ[ьи]|милостын[я]?|фонд[а]?)($|[^а-яa-z0-9])/i, 'благотворительность'],
  [/(^|[^а-яa-z0-9])(проезд|автобус|маршрутк[аи]|троллейбус|трамва[йя]|метро|билет[а]?|транспорт)($|[^а-яa-z0-9])/i, 'проезд в автобусах'],
  [/(^|[^а-яa-z0-9])(кредит[а]?|займ[а]?|ипотек[аи]|рассрочк[а]?|долг[а]?)($|[^а-яa-z0-9])/i, 'кредиты'],
]

app.get('/api/instances/:instanceId/suggest-category', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name } = req.query
    if (!name) return res.json({ category_id: null, category: '', confidence: 0 })
    const words = String(name).trim().split(/\s+/).filter((w) => w.length >= 2)
    if (!words.length) return res.json({ category_id: null, category: '', confidence: 0 })
    const conditions = words.map((_, i) => `t.name ILIKE $${i + 2}`)
    const params = [req.instanceId, ...words.map((w) => `%${w}%`)]
    const { rows } = await pool.query(
      `SELECT c.id as category_id, c.name as category, COUNT(*) as cnt
       FROM transactions t LEFT JOIN categories c ON c.id = t.category_id
       WHERE t.instance_id = $1 AND (${conditions.join(' OR ')}) AND t.category_id IS NOT NULL
         AND NOT EXISTS (
           SELECT 1 FROM category_hidden h
           WHERE h.instance_id = $1 AND h.category_id = c.id
         )
       GROUP BY c.id, c.name ORDER BY cnt DESC LIMIT 3`,
      params
    )
    if (!rows.length) {
      // Fallback: keyword-based suggestion for new instances with no history
      const lower = name.toLowerCase()
      for (const [pattern, cat] of CATEGORY_KEYWORDS) {
        if (pattern.test(lower)) {
          const { rows: catRows } = await pool.query(
            `SELECT id, name FROM categories 
             WHERE (instance_id = $1 OR instance_id IS NULL) 
               AND LOWER(name) = LOWER($2)
               AND NOT EXISTS (
                 SELECT 1 FROM category_hidden h
                 WHERE h.instance_id = $1 AND h.category_id = categories.id
               )
             ORDER BY (instance_id = $1) DESC NULLS LAST LIMIT 1`,
            [req.instanceId, cat]
          )
          const category_id = catRows.length > 0 ? catRows[0].id : null
          const category_name = catRows.length > 0 ? catRows[0].name : cat
          return res.json({ category_id: category_id, category: category_name, confidence: 60, alternatives: [] })
        }
      }
      return res.json({ category_id: null, category: '', confidence: 0 })
    }
    const total = rows.reduce((s, r) => s + parseInt(r.cnt), 0)
    const best = rows[0]
    const confidence = Math.min(Math.round((parseInt(best.cnt) / total) * 100), 100)
    res.json({
      category_id: best.category_id,
      category: best.category,
      confidence: confidence,
      alternatives: rows.slice(1).map(r => ({ category_id: r.category_id, category: r.category, confidence: Math.round((parseInt(r.cnt) / total) * 100) }))
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})


// ==================== PARSE RECEIPT (instance-scoped) ====================

app.post('/api/instances/:instanceId/parse-receipt', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { text } = req.body
    if (!text || !text.trim()) return res.status(400).json({ error: 'No text provided' })
    const prompt = `Ты парсер кассовых чеков. Извлеки товары из текста чека. Верни ТОЛЬКО JSON массив, без пояснений.
Формат: [{"name": "название товара", "price": число, "quantity": число}]
Правила:
- Цена и количество — числа (не строки)
- Если количество не указано, ставь 1
- Игнорируй строки с ИТОГО, СУММА, СДАЧА, НДС, ИНН, дату, адрес, номер чека
- Название товара — очисти от артикулов и кодов, оставь человекочитаемое название
- Если не можешь распознать ни одного товара, верни []

Текст чека:
${text}`
    const geminiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
      }
    )
    const geminiData = await geminiRes.json()
    const content = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || '[]'
    const jsonMatch = content.match(/\[[\s\S]*\]/)
    const items = jsonMatch ? JSON.parse(jsonMatch[0]) : []
    res.json({ items })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== CATEGORIES ====================

app.get('/api/categories', authMiddleware, async (req, res) => {
  try {
    const { type } = req.query
    const conditions = ['instance_id IS NULL']
    const params = []
    let i = 1
    if (type) { conditions.push(`type = $${i++}`); params.push(type) }
    const where = `WHERE ${conditions.join(' AND ')}`
    const { rows } = await pool.query(
      `SELECT id, name, type, is_default FROM categories ${where} ORDER BY type, name`,
      params
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/categories', authMiddleware, async (req, res) => {
  try {
    const { name, type } = req.body
    if (!name || !type) return res.status(400).json({ error: 'Name and type required' })
    if (SERVICE_CATEGORY_NAMES.has(String(name).trim())) return res.status(400).json({ error: 'Служебная категория' })
    const { rows } = await pool.query(
      `INSERT INTO categories (name, type, instance_id, is_default)
       VALUES ($1, $2, NULL, FALSE)
       ON CONFLICT ((COALESCE(instance_id, 0)), name) DO UPDATE SET type = excluded.type
       RETURNING *`,
      [name, type]
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/categories/:id', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT name FROM categories WHERE id = $1', [req.params.id])
    if (!rows.length) return res.status(404).json({ error: 'Category not found' })
    if (SERVICE_CATEGORY_NAMES.has(rows[0].name)) return res.status(400).json({ error: 'Служебная категория' })
    const { rowCount } = await pool.query('DELETE FROM categories WHERE id = $1', [req.params.id])
    if (!rowCount) return res.status(404).json({ error: 'Category not found' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== DASHBOARD (instance-scoped) ====================

app.get('/api/instances/:instanceId/dashboard', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { period, year, month, quarter } = req.query
    const now = new Date()
    const curYear = now.getFullYear()
    const curMonth = now.getMonth() + 1

    let fromDate, toDate
    const y = year ? parseInt(year) : curYear

    if (period === 'month' || !period) {
      const m = month ? parseInt(month) : curMonth
      fromDate = `${y}-${String(m).padStart(2, '0')}-01`
      toDate = m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, '0')}-01`
    } else if (period === 'quarter') {
      const q = quarter ? parseInt(quarter) : Math.ceil(curMonth / 3)
      const startMonth = (q - 1) * 3 + 1
      fromDate = `${y}-${String(startMonth).padStart(2, '0')}-01`
      toDate = startMonth + 3 > 12 ? `${y + 1}-01-01` : `${y}-${String(startMonth + 3).padStart(2, '0')}-01`
    } else if (period === 'year') {
      fromDate = `${y}-01-01`
      toDate = `${y + 1}-01-01`
    }

    const conditions = ['t.instance_id = $1', '(t.is_planned IS FALSE OR t.is_planned IS NULL)']
    const params = [req.instanceId]
    let i = 2
    if (fromDate) { conditions.push(`t.date >= $${i++}`); params.push(fromDate) }
    if (toDate) { conditions.push(`t.date < $${i++}`); params.push(toDate) }
    const where = `WHERE ${conditions.join(' AND ')}`


    const { rows: totals } = await pool.query(
      `SELECT t.type, SUM(t.amount) as total, COUNT(*) as count
       FROM transactions t ${where} GROUP BY t.type`,
      params
    )

    const { rows: byCategory } = await pool.query(
      `SELECT t.type, c.name as category, SUM(t.amount) as total, COUNT(*) as count
       FROM transactions t LEFT JOIN categories c ON c.id = t.category_id
       ${where} AND t.category_id IS NOT NULL GROUP BY t.type, c.id, c.name ORDER BY t.type, total DESC`,
      params
    )

    const { rows: byMonth } = await pool.query(
      `SELECT TO_CHAR(t.date, 'YYYY-MM') as month, t.type, SUM(t.amount) as total, COUNT(*) as count
       FROM transactions t ${where} GROUP BY month, t.type ORDER BY month ASC`,
      params
    )

    const { rows: savingsByType } = await pool.query(
      `SELECT t.savings_type, SUM(t.amount) as total, COUNT(*) as count
       FROM transactions t ${where} AND t.type = 'savings' GROUP BY t.savings_type`,
      params
    )

    const { rows: recent } = await pool.query(
      `SELECT ${CATEGORY_SELECT}, t.savings_type FROM transactions t ${CATEGORY_JOIN} ${where} ORDER BY t.date DESC, t.id DESC LIMIT 10`,
      params
    )

    
    const expenseTotal = totals.find(t => t.type === 'expense')?.total || 0
    const incomeTotal = totals.find(t => t.type === 'income')?.total || 0
    const savingsTotal = totals.find(t => t.type === 'savings')?.total || 0
    const withdrawalsTotal = savingsByType.find(s => s.savings_type === 'withdrawal')?.total || 0
    const savingsCount = totals.find(t => t.type === 'savings')?.count || 0
    const savingsIn = savingsByType
      .filter(s => s.savings_type !== 'withdrawal' && s.savings_type !== 'adjustment')
      .reduce((sum, s) => sum + parseFloat(s.total || 0), 0)
    const savingsInCount = savingsByType
      .filter(s => s.savings_type !== 'withdrawal' && s.savings_type !== 'adjustment')
      .reduce((sum, s) => sum + parseInt(s.count || 0), 0)
    const creditsRow = byCategory.find(c => c.type === 'expense' && c.category === 'кредиты')
    const creditsTotal = creditsRow ? parseFloat(creditsRow.total) : 0
    const creditsCount = creditsRow ? parseInt(creditsRow.count) : 0

    res.json({
      period: { from: fromDate, to: toDate, period: period || 'month', year: y, month: month ? parseInt(month) : curMonth, quarter: quarter ? parseInt(quarter) : Math.ceil(curMonth / 3) },
      summary: {
        expense: { total: parseFloat(expenseTotal), count: parseInt(totals.find(t => t.type === 'expense')?.count || 0) },
        income: { total: parseFloat(incomeTotal), count: parseInt(totals.find(t => t.type === 'income')?.count || 0) },
        savings: { total: parseFloat(savingsTotal), count: parseInt(savingsCount) },
        withdrawals: { total: parseFloat(withdrawalsTotal), count: parseInt(savingsByType.find(s => s.savings_type === 'withdrawal')?.count || 0) },
        savingsIn: { total: parseFloat(savingsIn), count: parseInt(savingsInCount) },
        credits: { total: parseFloat(creditsTotal), count: parseInt(creditsCount) },
        balance: parseFloat(incomeTotal) - parseFloat(expenseTotal) - parseFloat(savingsTotal) + parseFloat(withdrawalsTotal)
      },
      byCategory,
      byMonth,
      recent
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== ADMIN ROUTES ====================

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, is_admin, plan, plan_expires_at, created_at FROM users ORDER BY created_at DESC'
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/admin/users/:userId/admin', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId)
    const { is_admin } = req.body
    const { rows } = await pool.query(
      'UPDATE users SET is_admin = $1 WHERE id = $2 RETURNING id, username, is_admin, plan, plan_expires_at',
      [is_admin, userId]
    )
    if (!rows.length) return res.status(404).json({ error: 'User not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/admin/users/:userId/plan', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId)
    const { plan, plan_expires_at } = req.body
    if (plan && !['free', 'pro', 'family'].includes(plan)) {
      return res.status(400).json({ error: 'Неверный тариф. Допустимые: free, pro, family' })
    }
    const { rows } = await pool.query(
      'UPDATE users SET plan = COALESCE($1, plan), plan_expires_at = $2 WHERE id = $3 RETURNING id, username, is_admin, plan, plan_expires_at',
      [plan || null, plan_expires_at || null, userId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Пользователь не найден' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId)
    if (userId === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' })
    const { rowCount } = await pool.query('DELETE FROM users WHERE id = $1', [userId])
    if (!rowCount) return res.status(404).json({ error: 'User not found' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/admin/instances', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT i.id, i.name, i.created_at, u.username as owner,
              (SELECT COUNT(*) FROM instance_members m WHERE m.instance_id = i.id) as member_count
       FROM instances i
       JOIN users u ON u.id = i.owner_id
       ORDER BY i.created_at DESC`
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/admin/instances/:instanceId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const instanceId = parseInt(req.params.instanceId)
    const { name } = req.body
    const { rows } = await pool.query('UPDATE instances SET name = $1 WHERE id = $2 RETURNING *', [name, instanceId])
    if (!rows.length) return res.status(404).json({ error: 'Instance not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/members', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const instanceId = parseInt(req.params.instanceId)
    const { user_id, role } = req.body
    await pool.query(
      'INSERT INTO instance_members (instance_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT (instance_id, user_id) DO UPDATE SET role = $3',
      [instanceId, user_id, role || 'member']
    )
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/members/:userId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const instanceId = parseInt(req.params.instanceId)
    const userId = parseInt(req.params.userId)
    const { rowCount } = await pool.query(
      "DELETE FROM instance_members WHERE instance_id = $1 AND user_id = $2 AND role != 'owner'",
      [instanceId, userId]
    )
    if (!rowCount) return res.status(404).json({ error: 'Member not found or is owner' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/admin/instances/:instanceId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const instanceId = parseInt(req.params.instanceId)
    const { rowCount } = await pool.query('DELETE FROM instances WHERE id = $1', [instanceId])
    if (!rowCount) return res.status(404).json({ error: 'Instance not found' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users) as user_count,
        (SELECT COUNT(*) FROM instances) as instance_count,
        (SELECT COUNT(*) FROM transactions) as transaction_count,
        (SELECT COUNT(*) FROM join_requests WHERE status = 'pending') as pending_requests
    `)
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== FEATURE 1: BANK STATEMENT IMPORT (XLSX/CSV) ====================

const uploadStatement = multer({ limits: { fileSize: 10 * 1024 * 1024 } })

app.post('/api/instances/:instanceId/import-statement', authMiddleware, instanceMiddleware, uploadStatement.single('file'), async (req, res) => {
  try {
    if (req.user.is_demo) {
      return res.status(403).json({ error: 'Импорт выписок недоступен в демо-режиме.' })
    }

    const planInfo = await getUserPlanInfo(req.user.id)
    if (!planInfo.is_admin && !planInfo.limits.allowImportXlsx) {
      return res.status(403).json({
        error: `Импорт выписок доступен только на тарифах "PRO Личный" и "Семья & Бизнес".`
      })
    }

    if (!req.file) return res.status(400).json({ error: 'Файл выписки не передан' })

    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' })
    const sheetName = workbook.SheetNames[0]
    const rawData = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { defval: '' })


    if (!rawData.length) {
      return res.status(400).json({ error: 'Файл выписки пуст или не содержит распознанных строк' })
    }


    let importedCount = 0
    let skippedCount = 0

    for (const row of rawData) {
      // Flexibly map column names from Sber, Tinkoff, VTB, Alfa or standard templates
      const dateRaw = row['Дата'] || row['Дата операции'] || row['Date'] || row['Дата и время'] || row['Дата платежа']
      const nameRaw = row['Название'] || row['Описание'] || row['Description'] || row['Категория/Описание'] || row['Контрагент'] || row['Назначение платежа'] || 'Импортированная операция'
      const amountRaw = row['Сумма'] || row['Сумма операции'] || row['Amount'] || row['Сумма платежа'] || row['Расход'] || row['Доход']
      const typeRaw = row['Тип'] || row['Type'] || row['Статус'] || ''

      if (!dateRaw || amountRaw === '' || amountRaw === undefined) {
        skippedCount++
        continue
      }

      let amount = parseFloat(String(amountRaw).replace(/\s+/g, '').replace(',', '.'))
      if (isNaN(amount) || amount === 0) {
        skippedCount++
        continue
      }

      let type = 'expense'
      if (amount > 0) {
        if (typeRaw.toLowerCase().includes('доход') || typeRaw.toLowerCase().includes('пополнение') || typeRaw.toLowerCase().includes('income')) {
          type = 'income'
        } else if (String(amountRaw).includes('+')) {
          type = 'income'
        }
      } else {
        amount = Math.abs(amount)
        type = 'expense'
      }

      // Format date to YYYY-MM-DD
      let dateFormatted = new Date().toISOString().split('T')[0]
      if (typeof dateRaw === 'number') {
        // Excel serial date number
        const jsDate = new Date(Math.round((dateRaw - 25569) * 86400 * 1000))
        if (!isNaN(jsDate.getTime())) dateFormatted = jsDate.toISOString().split('T')[0]
      } else if (typeof dateRaw === 'string') {
        const parts = dateRaw.trim().split(/[\.\/\-]/)
        if (parts.length === 3) {
          if (parts[0].length === 4) {
            dateFormatted = `${parts[0]}-${parts[1].padStart(2, '0')}-${parts[2].padStart(2, '0')}`
          } else if (parts[2].length === 4) {
            dateFormatted = `${parts[2]}-${parts[1].padStart(2, '0')}-${parts[0].padStart(2, '0')}`
          }
        }
      }

      const txName = String(nameRaw).trim() || 'Операция из выписки'
      
      // Auto-categorize
      let catName = 'Продукты'
      const nLower = txName.toLowerCase()
      if (type === 'income') catName = 'Зарплата'
      else if (nLower.includes('перевод') || nLower.includes('сбп')) catName = 'Переводы'
      else if (nLower.includes('такси') || nLower.includes('каршеринг') || nLower.includes('транспорт')) catName = 'Транспорт'
      else if (nLower.includes('кофе') || nLower.includes('ресторан') || nLower.includes('кафе')) catName = 'Кафе и рестораны'
      else if (nLower.includes('аптека') || nLower.includes('клиника')) catName = 'Здоровье'
      else if (nLower.includes('аренда') || nLower.includes('жку') || nLower.includes('коммунал')) catName = 'ЖКХ'

      const { rows: catRows } = await pool.query(
        'SELECT id FROM categories WHERE name = $1 AND (instance_id = $2 OR instance_id IS NULL) LIMIT 1',
        [catName, req.instanceId]
      )
      let categoryId = catRows.length ? catRows[0].id : null
      if (!categoryId) {
        const { rows: newCat } = await pool.query(
          'INSERT INTO categories (name, type, instance_id) VALUES ($1, $2, $3) RETURNING id',
          [catName, type, req.instanceId]
        )
        categoryId = newCat[0].id
      }

      const txId = 'imp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7)

      await pool.query(
        `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id)
         VALUES ($1, $2, $3, $4, $5, $6, 'Импорт выписки', $7)`,
        [txId, txName, dateFormatted, type, amount, categoryId, req.instanceId]
      )
      importedCount++
    }

    res.json({
      ok: true,
      message: `Успешно импортировано операций: ${importedCount} (Пропущено: ${skippedCount})`,
      imported_count: importedCount,
      skipped_count: skippedCount
    })
  } catch (err) {
    res.status(500).json({ error: 'Ошибка импорта выписки: ' + err.message })
  }
})

// Export transactions to XLSX (compatible with import-statement format)
app.get('/api/instances/:instanceId/export-xlsx', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT t.date, t.name, t.amount, t.type, c.name as category, t.comment
       FROM transactions t
       LEFT JOIN categories c ON c.id = t.category_id
       WHERE t.instance_id = $1
       ORDER BY t.date DESC`,
      [req.instanceId]
    )

    const data = rows.map(r => ({
      'Дата': r.date ? new Date(r.date).toISOString().slice(0, 10) : '',
      'Название': r.name || '',
      'Сумма': parseFloat(r.amount) || 0,
      'Тип': r.type === 'expense' ? 'Расход' : (r.type === 'income' ? 'Доход' : 'Накопления'),
      'Категория': r.category || '',
      'Комментарий': r.comment || ''
    }))

    const worksheet = XLSX.utils.json_to_sheet(data)
    const workbook = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Выписка')

    const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' })

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    res.setHeader('Content-Disposition', `attachment; filename="transactions_${req.instanceId}.xlsx"`)
    res.send(buffer)
  } catch (err) {
    res.status(500).json({ error: 'Ошибка экспорта в XLSX: ' + err.message })
  }
})

// ==================== FEATURE 3: GEMINI AI FINANCIAL ADVISOR ====================

app.get('/api/instances/:instanceId/ai-advice', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    if (req.user.is_demo) {
      return res.status(403).json({ error: 'AI-Советник недоступен в демо-режиме.' })
    }

    const planInfo = await getUserPlanInfo(req.user.id)
    if (!planInfo.is_admin) {
      if (!planInfo.limits.allowAiAdvisor) {
        return res.status(403).json({
          error: `AI-Советник доступен на тарифах "PRO Личный" и "Семья & Бизнес".`
        })
      }
      const { rows: aiCountRows } = await pool.query(
        `SELECT COUNT(*) FROM user_actions_log
         WHERE user_id = $1 AND action_type = 'ai_advice'
           AND created_at >= date_trunc('month', CURRENT_DATE)`,
        [req.user.id]
      )
      const currentAdvices = parseInt(aiCountRows[0].count) || 0
      if (currentAdvices >= planInfo.limits.monthlyAiAdvices) {
        return res.status(429).json({
          error: `Достигнут ежемесячный лимит ${planInfo.limits.monthlyAiAdvices} AI-советов для тарифа "${planInfo.name}".`
        })
      }
    }

    if (!process.env.GEMINI_API_KEY) {
      return res.status(500).json({ error: 'Ключ Gemini API не настроен' })
    }

    // Fetch month statistics
    const { rows: txStats } = await pool.query(
      `SELECT t.type, c.name as category_name, SUM(t.amount) as total_amount, COUNT(*) as tx_count
       FROM transactions t
       LEFT JOIN categories c ON c.id = t.category_id
       WHERE t.instance_id = $1 AND t.date >= (CURRENT_DATE - INTERVAL '30 days')
       GROUP BY t.type, c.name ORDER BY total_amount DESC`,
      [req.instanceId]
    )

    const { rows: savings } = await pool.query(
      `SELECT name, current_amount, target_amount FROM savings_goals WHERE instance_id = $1 AND is_completed = FALSE`,
      [req.instanceId]
    )

    const { rows: credits } = await pool.query(
      `SELECT name, remaining_amount, monthly_payment FROM credits WHERE instance_id = $1 AND remaining_amount > 0`,
      [req.instanceId]
    )

    const expensesSummary = txStats
      .filter(r => r.type === 'expense')
      .map(r => `• ${r.category_name || 'Прочее'}: ${parseFloat(r.total_amount).toFixed(0)} ₽ (${r.tx_count} операций)`)
      .join('\n')

    const incomesSummary = txStats
      .filter(r => r.type === 'income')
      .map(r => `• ${r.category_name || 'Доход'}: ${parseFloat(r.total_amount).toFixed(0)} ₽`)
      .join('\n')

    const savingsSummary = savings
      .map(s => `• Цель "${s.name}": накоплено ${s.current_amount} ₽ из ${s.target_amount} ₽`)
      .join('\n')

    const creditsSummary = credits
      .map(c => `• Кредит "${c.name}": остаток ${c.remaining_amount} ₽ (платеж ${c.monthly_payment} ₽/мес)`)
      .join('\n')

    const prompt = `Ты профессиональный персональный финансовый советник и аналитик бюджета.
Проанализируй финансовые данные пользователя за последние 30 дней и дай 3-4 конкретных, прагматичных и мотивирующих совета на русском языке.

ДАННЫЕ ПОЛЬЗОВАТЕЛЯ:
--- Расходы за 30 дней ---
${expensesSummary || 'Данных о расходах нет'}

--- Доходы за 30 дней ---
${incomesSummary || 'Данных о доходах нет'}

--- Финансовые цели и накопления ---
${savingsSummary || 'Целей нет'}

--- Кредиты и долги ---
${creditsSummary || 'Кредитов нет'}

ТРЕБОВАНИЯ К ОТВЕТУ:
- Напиши ответ в дружелюбном, наглядном стиле с эмодзи.
- Отметь топ-категории расходов, похвали за успехи в накоплениях, укажи на риски или возможности сэкономить.
- Раздели ответ на секции: 📊 Анализ месяца, 💡 Персональные рекомендации, 🚀 Шаг недели.
- Используй GitHub Markdown formatting.`

    const geminiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
      }
    )

    const geminiData = await geminiRes.json()
    const adviceText = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || 'Не удалось сформировать рекомендацию.'

    // Log action to user_actions_log
    if (!req.user.is_demo) {
      await pool.query(
        `INSERT INTO user_actions_log (user_id, instance_id, action_type, entity_type) VALUES ($1, $2, 'ai_advice', 'gemini')`,
        [req.user.id, req.instanceId]
      ).catch(console.error)
    }

    res.json({ advice: adviceText })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== FEATURE 4: iCAL RECURRING CALENDAR (.ics) ====================

app.get('/api/instances/:instanceId/calendar.ics', async (req, res) => {
  try {
    const instanceId = parseInt(req.params.instanceId)
    const { rows: inst } = await pool.query('SELECT name FROM instances WHERE id = $1', [instanceId])
    if (!inst.length) return res.status(404).send('Instance not found')

    const { rows: credits } = await pool.query(
      'SELECT name, monthly_payment, payment_day FROM credits WHERE instance_id = $1 AND remaining_amount > 0',
      [instanceId]
    )

    const { rows: recurringTx } = await pool.query(
      `SELECT name, amount, date, comment FROM transactions 
       WHERE instance_id = $1 AND (comment ILIKE '%подписка%' OR comment ILIKE '%аренда%' OR comment ILIKE '%жку%' OR comment ILIKE '%регуляр%')
       ORDER BY date DESC LIMIT 20`,
      [instanceId]
    )

    let icsContent = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//TIIN Finance//Recurring Payments Calendar//RU',
      'CALSCALE:GREGORIAN',
      'METHOD:PUBLISH',
      `X-WR-CALNAME: TIIN Finance — ${inst[0].name}`,
      'X-WR-TIMEZONE:UTC'
    ]

    const now = new Date()
    const curYear = now.getFullYear()
    const curMonth = String(now.getMonth() + 1).padStart(2, '0')

    // Add Credit Monthly Payments
    for (const credit of credits) {
      const pDay = String(credit.payment_day || 10).padStart(2, '0')
      const dtStart = `${curYear}${curMonth}${pDay}T090000Z`
      icsContent.push(
        'BEGIN:VEVENT',
        `SUMMARY:💳 Платеж по кредиту: ${credit.name} (${credit.monthly_payment} ₽)`,
        `DESCRIPTION:Ежемесячный обязательный платеж по кредиту ${credit.name} в размере ${credit.monthly_payment} руб.`,
        `DTSTART:${dtStart}`,
        `DTEND:${dtStart}`,
        'RRULE:FREQ=MONTHLY',
        `UID:credit-${instanceId}-${credit.name.replace(/\s+/g, '')}@finance.tiinservice.online`,
        'END:VEVENT'
      )
    }

    // Add Recurring Subscriptions
    for (const tx of recurringTx) {
      const txDate = new Date(tx.date)
      const dayStr = String(txDate.getDate() || 1).padStart(2, '0')
      const dtStart = `${curYear}${curMonth}${dayStr}T100000Z`
      icsContent.push(
        'BEGIN:VEVENT',
        `SUMMARY:🔄 Списание: ${tx.name} (${tx.amount} ₽)`,
        `DESCRIPTION:Регулярный платеж / подписка: ${tx.comment || tx.name}`,
        `DTSTART:${dtStart}`,
        `DTEND:${dtStart}`,
        'RRULE:FREQ=MONTHLY',
        `UID:sub-${instanceId}-${tx.name.replace(/\s+/g, '')}@finance.tiinservice.online`,
        'END:VEVENT'
      )
    }

    icsContent.push('END:VCALENDAR')

    res.setHeader('Content-Type', 'text/calendar; charset=utf-8')
    res.setHeader('Content-Disposition', `inline; filename="tiin_finance_${instanceId}.ics"`)
    res.send(icsContent.join('\r\n'))
  } catch (err) {
    res.status(500).send('Calendar generation failed')
  }
})


// ==================== ADMIN PANEL UI ====================

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin.html'))
})

app.get('/finance-admin-panel', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin.html'))
})


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/app.html'))
})

// ==================== HEALTH ====================

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1')
    res.json({ status: 'ok' })
  } catch {
    res.status(500).json({ status: 'error', message: 'DB connection failed' })
  }
})

import { startBot } from './bot.js'

// Initialize demo mode & background cleanup timer
initDemoAccounts().catch(console.error)
setInterval(cleanupExpiredDemoSessions, 30 * 1000)

// Start Telegram Bot Polling
startBot()

app.listen(PORT, () => {
  console.log(`Finance API running on port ${PORT}`)
})



