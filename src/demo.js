import pool from './db.js'
import { hashPassword, signToken } from './auth.js'

export const DEMO_ACCOUNTS_COUNT = 5
export const DEMO_SESSION_DURATION_MS = 20 * 60 * 1000 // 20 minutes
export const MAX_RECEIPT_SCANS_PER_SESSION = 3

const DEMO_USER_PREFIX = 'demo_guest_'

// Initialize 5 fixed demo accounts & instances in DB
export async function initDemoAccounts() {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')

    // Create table demo_sessions if not exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS demo_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        instance_id INTEGER UNIQUE NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
        slot_number INTEGER UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'free' CHECK (status IN ('free', 'busy')),
        occupied_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ,
        session_token TEXT,
        receipt_scans_left INTEGER DEFAULT ${MAX_RECEIPT_SCANS_PER_SESSION},
        last_reset_at TIMESTAMPTZ DEFAULT NOW()
      )
    `)

    const defaultPasswordHash = await hashPassword('DemoGuestPass123!')

    for (let slot = 1; slot <= DEMO_ACCOUNTS_COUNT; slot++) {
      const username = `${DEMO_USER_PREFIX}${slot}`
      
      // Ensure user exists
      let userRes = await client.query('SELECT id FROM users WHERE username = $1', [username])
      let userId
      if (!userRes.rows.length) {
        const newUser = await client.query(
          'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id',
          [username, defaultPasswordHash]
        )
        userId = newUser.rows[0].id
      } else {
        userId = userRes.rows[0].id
      }

      // Ensure instance exists
      let instRes = await client.query(
        'SELECT i.id FROM instances i JOIN instance_members im ON i.id = im.instance_id WHERE im.user_id = $1 AND im.role = \'owner\'',
        [userId]
      )
      let instanceId
      if (!instRes.rows.length) {
        const newInst = await client.query(
          'INSERT INTO instances (name, owner_id) VALUES ($1, $2) RETURNING id',
          [`Демо-Бюджет №${slot}`, userId]
        )
        instanceId = newInst.rows[0].id
        await client.query(
          'INSERT INTO instance_members (instance_id, user_id, role) VALUES ($1, $2, \'owner\') ON CONFLICT DO NOTHING',
          [instanceId, userId]
        )
      } else {
        instanceId = instRes.rows[0].id
      }

      // Ensure entry in demo_sessions
      await client.query(`
        INSERT INTO demo_sessions (user_id, instance_id, slot_number, status, receipt_scans_left)
        VALUES ($1, $2, $3, 'free', $4)
        ON CONFLICT (slot_number) DO UPDATE SET user_id = EXCLUDED.user_id, instance_id = EXCLUDED.instance_id
      `, [userId, instanceId, slot, MAX_RECEIPT_SCANS_PER_SESSION])
    }

    await client.query('COMMIT')
    console.log(`[Demo] ${DEMO_ACCOUNTS_COUNT} demo accounts initialized`)
  } catch (err) {
    await client.query('ROLLBACK')
    console.error('[Demo] Initialization failed:', err)
  } finally {
    client.release()
  }
}

// Reset an instance data completely (or seed initial default categories)
export async function clearDemoInstanceData(instanceId) {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')

    await client.query('DELETE FROM transactions WHERE instance_id = $1', [instanceId])
    await client.query('DELETE FROM shopping_items WHERE instance_id = $1', [instanceId])
    await client.query('DELETE FROM credit_payments WHERE credit_id IN (SELECT id FROM credits WHERE instance_id = $1)', [instanceId])
    await client.query('DELETE FROM credits WHERE instance_id = $1', [instanceId])
    await client.query('DELETE FROM savings_goals WHERE instance_id = $1', [instanceId])
    await client.query('DELETE FROM category_hidden WHERE instance_id = $1', [instanceId])
    await client.query('DELETE FROM accounts WHERE instance_id = $1', [instanceId])
    await client.query('DELETE FROM categories WHERE instance_id = $1', [instanceId])
    await client.query('DELETE FROM user_actions_log WHERE instance_id = $1', [instanceId])

    // Create default accounts & categories for demo
    const accRes = await client.query(
      `INSERT INTO accounts (instance_id, name, currency, type) VALUES ($1, 'Основная карта', 'RUB', 'card') RETURNING id`,
      [instanceId]
    )
    const cardAccId = accRes.rows[0].id

    await client.query(
      `INSERT INTO accounts (instance_id, name, currency, type) VALUES ($1, 'Наличные', 'RUB', 'cash')`,
      [instanceId]
    )

    await client.query('COMMIT')
    return { cardAccId }
  } catch (err) {
    await client.query('ROLLBACK')
    throw err
  } finally {
    client.release()
  }
}

// Seed realistic mock data into demo instance
export async function seedDemoInstanceData(instanceId) {
  await clearDemoInstanceData(instanceId)

  const client = await pool.connect()
  try {
    await client.query('BEGIN')

    // Fetch accounts
    const accs = await client.query('SELECT id, type FROM accounts WHERE instance_id = $1', [instanceId])
    const cardId = accs.rows.find(a => a.type === 'card')?.id || accs.rows[0]?.id

    // Categories creation
    const catDefs = [
      { name: 'Продукты', type: 'expense' },
      { name: 'Кафе и еда', type: 'expense' },
      { name: 'Авто и транспорт', type: 'expense' },
      { name: 'Коммуналка и Инет', type: 'expense' },
      { name: 'Одежда и покупки', type: 'expense' },
      { name: 'Развлечения', type: 'expense' },
      { name: 'Зарплата', type: 'income' },
      { name: 'Фриланс / Премии', type: 'income' },
      { name: 'Накопления', type: 'savings' }
    ]

    const catMap = {}
    for (const c of catDefs) {
      const res = await client.query(
        'INSERT INTO categories (name, type, instance_id, is_default) VALUES ($1, $2, $3, FALSE) RETURNING id',
        [c.name, c.type, instanceId]
      )
      catMap[c.name] = res.rows[0].id
    }

    // Savings goals
    const goalRes = await client.query(
      `INSERT INTO savings_goals (name, target_amount, current_amount, instance_id, comment)
       VALUES ('Отпуск на море', 150000, 45000, $1, 'Направление: Сочи') RETURNING id`,
      [instanceId]
    )
    const goalId = goalRes.rows[0].id

    // Credits
    const credRes = await client.query(
      `INSERT INTO credits (name, instance_id, lender, total_amount, interest_rate, monthly_payment, remaining_amount, payment_day)
       VALUES ('Автокредит', $1, 'Сбербанк', 600000, 14.5, 18500, 320000, 15) RETURNING id`,
      [instanceId]
    )
    const creditId = credRes.rows[0].id

    // Generate transactions for the last 60 days
    const now = new Date()
    const txs = [
      // Income
      { daysAgo: 45, name: 'Аванс по ЗП', amount: 65000, type: 'income', cat: 'Зарплата' },
      { daysAgo: 30, name: 'Основная зарплата', amount: 85000, type: 'income', cat: 'Зарплата' },
      { daysAgo: 15, name: 'Премия за проект', amount: 25000, type: 'income', cat: 'Фриланс / Премии' },
      { daysAgo: 2, name: 'Аванс по ЗП', amount: 65000, type: 'income', cat: 'Зарплата' },
      
      // Regular Expenses
      { daysAgo: 58, name: 'Супермаркет Пятерочка', amount: 3420, type: 'expense', cat: 'Продукты' },
      { daysAgo: 55, name: 'Заправка АЗС', amount: 2500, type: 'expense', cat: 'Авто и транспорт' },
      { daysAgo: 50, name: 'Заказ в Додо Пицца', amount: 1850, type: 'expense', cat: 'Кафе и еда' },
      { daysAgo: 45, name: 'Оплата КУ и мобильный', amount: 6800, type: 'expense', cat: 'Коммуналка и Инет' },
      { daysAgo: 40, name: 'Покупка джинс и футболки', amount: 7900, type: 'expense', cat: 'Одежда и покупки' },
      { daysAgo: 35, name: 'Кино и попкорн', amount: 1400, type: 'expense', cat: 'Развлечения' },
      { daysAgo: 30, name: 'Супермаркет Лента', amount: 5600, type: 'expense', cat: 'Продукты' },
      { daysAgo: 28, name: 'Оплата автокредита', amount: 18500, type: 'expense', cat: 'Авто и транспорт' },
      { daysAgo: 22, name: 'ТО автомобиля', amount: 12000, type: 'expense', cat: 'Авто и транспорт' },
      { daysAgo: 18, name: 'Продукты ВкусВилл', amount: 2900, type: 'expense', cat: 'Продукты' },
      { daysAgo: 12, name: 'Кафе Кофейня №1', amount: 850, type: 'expense', cat: 'Кафе и еда' },
      { daysAgo: 8, name: 'Аптека и витамины', amount: 2150, type: 'expense', cat: 'Продукты' },
      { daysAgo: 5, name: 'Супермаркет Перекресток', amount: 4100, type: 'expense', cat: 'Продукты' },
      { daysAgo: 1, name: 'Ужин в ресторации', amount: 3600, type: 'expense', cat: 'Кафе и еда' },

      // Savings
      { daysAgo: 25, name: 'Пополнение на отпуск', amount: 15000, type: 'savings', cat: 'Накопления', goalId, savings_type: 'goal' }
    ]

    for (let i = 0; i < txs.length; i++) {
      const t = txs[i]
      const txDate = new Date(now.getTime() - t.daysAgo * 86400000).toISOString().split('T')[0]
      const txId = `demo_tx_${Date.now()}_${i}`
      const categoryId = catMap[t.cat]

      await client.query(
        `INSERT INTO transactions (id, name, date, type, amount, instance_id, account_id, category_id, goal_id, savings_type)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [txId, t.name, txDate, t.type, t.amount, instanceId, cardId, categoryId, t.goalId || null, t.savings_type || 'free']
      )
    }

    // Shopping items
    const shopItems = ['Молоко 3.2%', 'Хлеб зерновой', 'Кофе в зернах', 'Стиральный порошок', 'Яблоки Гала']
    for (const item of shopItems) {
      await client.query(
        'INSERT INTO shopping_items (name, instance_id, bought) VALUES ($1, $2, FALSE)',
        [item, instanceId]
      )
    }

    await client.query('COMMIT')
  } catch (err) {
    await client.query('ROLLBACK')
    throw err
  } finally {
    client.release()
  }
}

// Background cleanup procedure for expired sessions
export async function cleanupExpiredDemoSessions() {
  try {
    const { rows: expired } = await pool.query(
      `SELECT * FROM demo_sessions WHERE status = 'busy' AND expires_at < NOW()`
    )
    for (const session of expired) {
      console.log(`[Demo] Session expired for slot ${session.slot_number} (Instance: ${session.instance_id}). Resetting...`)
      await clearDemoInstanceData(session.instance_id)
      await pool.query(
        `UPDATE demo_sessions
         SET status = 'free', occupied_at = NULL, expires_at = NULL, session_token = NULL, receipt_scans_left = $1, last_reset_at = NOW()
         WHERE id = $2`,
        [MAX_RECEIPT_SCANS_PER_SESSION, session.id]
      )
    }
  } catch (err) {
    console.error('[Demo] Cleanup error:', err)
  }
}

// Get status of all 5 slots
export async function getDemoSlotsStatus() {
  await cleanupExpiredDemoSessions()
  const { rows } = await pool.query(`
    SELECT ds.slot_number, ds.status, ds.expires_at, u.username
    FROM demo_sessions ds
    JOIN users u ON ds.user_id = u.id
    ORDER BY ds.slot_number ASC
  `)
  
  return rows.map(r => ({
    slot: r.slot_number,
    status: r.status,
    expires_at: r.expires_at,
    seconds_remaining: r.expires_at ? Math.max(0, Math.floor((new Date(r.expires_at).getTime() - Date.now()) / 1000)) : 0
  }))
}

// Acquire a slot (login as guest)
export async function occupyDemoSlot(targetSlot = null) {
  await cleanupExpiredDemoSessions()
  const client = await pool.connect()
  try {
    await client.query('BEGIN')

    let slotQuery = `SELECT ds.*, u.username FROM demo_sessions ds JOIN users u ON ds.user_id = u.id WHERE ds.status = 'free'`
    const queryParams = []
    if (targetSlot) {
      slotQuery += ` AND ds.slot_number = $1`
      queryParams.push(targetSlot)
    }
    slotQuery += ` ORDER BY ds.slot_number ASC FOR UPDATE OF ds SKIP LOCKED`

    const { rows } = await client.query(slotQuery, queryParams)
    if (!rows.length) {
      await client.query('ROLLBACK')
      return { success: false, error: 'Все гостевые аккаунты сейчас заняты. Попробуйте чуть позже.' }
    }

    const session = rows[0]
    const expiresAt = new Date(Date.now() + DEMO_SESSION_DURATION_MS)

    // Generate token
    const token = signToken({
      id: session.user_id,
      username: session.username,
      is_admin: false,
      is_demo: true,
      demo_slot: session.slot_number,
      demo_instance_id: session.instance_id
    })

    // Seed mock data for new guest
    await seedDemoInstanceData(session.instance_id)

    await client.query(
      `UPDATE demo_sessions
       SET status = 'busy', occupied_at = NOW(), expires_at = $1, session_token = $2, receipt_scans_left = $3
       WHERE id = $4`,
      [expiresAt, token, MAX_RECEIPT_SCANS_PER_SESSION, session.id]
    )

    await client.query('COMMIT')
    return {
      success: true,
      token,
      user: { id: session.user_id, username: session.username, is_admin: false, is_demo: true },
      instance_id: session.instance_id,
      expires_at: expiresAt,
      seconds_remaining: Math.floor(DEMO_SESSION_DURATION_MS / 1000),
      receipt_scans_left: MAX_RECEIPT_SCANS_PER_SESSION
    }
  } catch (err) {
    await client.query('ROLLBACK')
    console.error('[Demo] Occupy slot error:', err)
    throw err
  } finally {
    client.release()
  }
}

// Release a slot manually (guest clicks 'Log out' or 'End demo')
export async function releaseDemoSlot(userId) {
  const { rows } = await pool.query('SELECT * FROM demo_sessions WHERE user_id = $1', [userId])
  if (!rows.length) return false
  const session = rows[0]
  await clearDemoInstanceData(session.instance_id)
  await pool.query(
    `UPDATE demo_sessions
     SET status = 'free', occupied_at = NULL, expires_at = NULL, session_token = NULL, receipt_scans_left = $1, last_reset_at = NOW()
     WHERE id = $2`,
    [MAX_RECEIPT_SCANS_PER_SESSION, session.id]
  )
  return true
}
