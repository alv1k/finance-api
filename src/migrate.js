import pool from './db.js'

const statements = [
  `CREATE TABLE IF NOT EXISTS users (
    id         SERIAL PRIMARY KEY,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    is_admin   BOOLEAN DEFAULT FALSE,
    plan       VARCHAR(20) DEFAULT 'free',
    plan_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS instances (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    owner_id   INTEGER NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS instance_members (
    id          SERIAL PRIMARY KEY,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    joined_at   TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (instance_id, user_id)
  )`,

  `CREATE TABLE IF NOT EXISTS join_requests (
    id          SERIAL PRIMARY KEY,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    UNIQUE (instance_id, user_id, status)
  )`,

  `CREATE TABLE IF NOT EXISTS transactions (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    date       DATE NOT NULL,
    type       TEXT NOT NULL DEFAULT 'expense' CHECK (type IN ('expense', 'income')),
    price      NUMERIC(10,2),
    quantity   NUMERIC(10,3),
    amount     NUMERIC(10,2) NOT NULL,
    category   TEXT DEFAULT '',
    comment    TEXT DEFAULT '',
    instance_id INTEGER REFERENCES instances(id) ON DELETE CASCADE
  )`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'expense'`,
  `ALTER TABLE transactions DROP CONSTRAINT IF EXISTS transactions_type_check`,
  `ALTER TABLE transactions ADD CONSTRAINT transactions_type_check CHECK (type IN ('expense', 'income', 'savings'))`,
  `CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(date)`,
  `CREATE INDEX IF NOT EXISTS idx_transactions_instance_id ON transactions(instance_id)`,
  `CREATE INDEX IF NOT EXISTS idx_instance_members_user_id ON instance_members(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_instance_members_instance_id ON instance_members(instance_id)`,
  `CREATE INDEX IF NOT EXISTS idx_join_requests_instance_id ON join_requests(instance_id)`,

  `CREATE TABLE IF NOT EXISTS categories (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL CHECK (type IN ('expense', 'income', 'savings')),
    instance_id INTEGER REFERENCES instances(id) ON DELETE CASCADE,
    is_default  BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS savings_goals (
    id            SERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    target_amount NUMERIC(12,2) NOT NULL,
    current_amount NUMERIC(12,2) DEFAULT 0,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    target_date   DATE,
    comment       TEXT DEFAULT '',
    created_at    TIMESTAMPTZ DEFAULT NOW()
  )`,

  `ALTER TABLE savings_goals ADD COLUMN IF NOT EXISTS is_completed BOOLEAN DEFAULT FALSE`,
  `ALTER TABLE savings_goals ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ`,
  `CREATE INDEX IF NOT EXISTS idx_savings_goals_completed ON savings_goals(instance_id, is_completed)`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS goal_id INTEGER`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS savings_type TEXT DEFAULT 'free'`,
  `ALTER TABLE transactions DROP CONSTRAINT IF EXISTS transactions_savings_type_check`,
  `ALTER TABLE transactions ADD CONSTRAINT transactions_savings_type_check CHECK (savings_type IN ('free', 'goal', 'withdrawal', 'adjustment'))`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS is_planned BOOLEAN DEFAULT FALSE`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS planned_date DATE`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS receipt_key TEXT DEFAULT NULL`,
  `CREATE INDEX IF NOT EXISTS idx_transactions_is_planned ON transactions(instance_id, is_planned, planned_date)`,
  `CREATE INDEX IF NOT EXISTS idx_transactions_receipt_key ON transactions(receipt_key)`,

  `CREATE TABLE IF NOT EXISTS credits (
    id               SERIAL PRIMARY KEY,
    name             TEXT NOT NULL,
    instance_id      INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    lender           TEXT DEFAULT '',
    total_amount     NUMERIC(12,2) NOT NULL,
    interest_rate    NUMERIC(5,2) DEFAULT 0,
    monthly_payment  NUMERIC(12,2) DEFAULT 0,
    start_date       DATE,
    end_date         DATE,
    remaining_amount NUMERIC(12,2),
    comment          TEXT DEFAULT '',
    created_at       TIMESTAMPTZ DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_credits_instance_id ON credits(instance_id)`,
  `ALTER TABLE credits ADD COLUMN IF NOT EXISTS payment_day INTEGER`,

  `CREATE TABLE IF NOT EXISTS credit_payments (
    id              SERIAL PRIMARY KEY,
    credit_id       INTEGER NOT NULL REFERENCES credits(id) ON DELETE CASCADE,
    amount          NUMERIC(12,2) NOT NULL,
    principal_amount NUMERIC(12,2) DEFAULT 0,
    interest_amount NUMERIC(12,2) DEFAULT 0,
    payment_date    DATE NOT NULL,
    comment         TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
  )`,
  `ALTER TABLE credit_payments ADD COLUMN IF NOT EXISTS payment_type TEXT DEFAULT 'regular' CHECK (payment_type IN ('regular', 'early'))`,
  `ALTER TABLE credit_payments ADD COLUMN IF NOT EXISTS early_strategy TEXT DEFAULT 'reduce_term' CHECK (early_strategy IN ('reduce_term', 'reduce_payment'))`,
  `CREATE INDEX IF NOT EXISTS idx_credit_payments_credit_id ON credit_payments(credit_id)`,
  `CREATE INDEX IF NOT EXISTS idx_credit_payments_date ON credit_payments(payment_date)`,

  `CREATE TABLE IF NOT EXISTS shopping_items (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    bought      BOOLEAN DEFAULT FALSE,
    created_by  INTEGER REFERENCES users(id),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_shopping_items_instance ON shopping_items(instance_id)`,

  `CREATE TABLE IF NOT EXISTS category_hidden (
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
    PRIMARY KEY (instance_id, category_id)
  )`,

  `CREATE TABLE IF NOT EXISTS user_actions_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    instance_id INTEGER REFERENCES instances(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    instance_id INTEGER REFERENCES instances(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    currency TEXT DEFAULT 'RUB',
    type TEXT DEFAULT 'card',
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,

  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL`,

  `CREATE TABLE IF NOT EXISTS telegram_finance_instances (
    id SERIAL PRIMARY KEY,
    tg_id BIGINT UNIQUE NOT NULL,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS plan VARCHAR(20) DEFAULT 'free'`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_expires_at TIMESTAMPTZ`,
  `CREATE INDEX IF NOT EXISTS idx_user_actions_log_lookup ON user_actions_log(user_id, action_type, created_at)`
]

try {
  for (const sql of statements) {
    await pool.query(sql)
  }
  console.log('Migration complete')

  // ============ Category normalization (idempotent) ============
  const client = await pool.connect()
  try {
    await client.query('BEGIN')

    await client.query('ALTER TABLE categories ADD COLUMN IF NOT EXISTS instance_id INTEGER REFERENCES instances(id) ON DELETE CASCADE')
    await client.query('ALTER TABLE categories ADD COLUMN IF NOT EXISTS is_default BOOLEAN DEFAULT FALSE')
    await client.query('ALTER TABLE categories DROP CONSTRAINT IF EXISTS categories_name_key')
    await client.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_categories_inst_name ON categories (COALESCE(instance_id, 0), name)')
    await client.query('UPDATE categories SET is_default = TRUE WHERE instance_id IS NULL AND is_default = FALSE')

    const defaultCats = [
      ['продукты', 'expense'], ['ЖКУ', 'expense'], ['автомобиль', 'expense'], ['здоровье', 'expense'],
      ['сладости', 'expense'], ['прочие нужды', 'expense'], ['развлечения', 'expense'], ['связь', 'expense'],
      ['подарки', 'expense'], ['одежда', 'expense'], ['питомцы', 'expense'], ['огород', 'expense'],
      ['хобби', 'expense'], ['готовая еда', 'expense'], ['доставка товаров', 'expense'], ['благотворительность', 'expense'],
      ['без классификации', 'expense'], ['проезд в автобусах', 'expense'], ['зп жена', 'income'], ['зп муж', 'income'],
      ['такси', 'income'], ['другой доход', 'income'], ['накопления', 'savings'], ['кредиты', 'expense'],
      ['Цели', 'savings'], ['Свободные накопления', 'savings'],
    ]
    for (const [name, type] of defaultCats) {
      await client.query(
        `INSERT INTO categories (name, type, is_default)
         SELECT $1, $2, TRUE
         WHERE NOT EXISTS (SELECT 1 FROM categories WHERE instance_id IS NULL AND name = $1)`,
        [name, type]
      )
    }

    await client.query('ALTER TABLE transactions ADD COLUMN IF NOT EXISTS category_id INTEGER REFERENCES categories(id)')

    const { rows: col } = await client.query(
      `SELECT 1 FROM information_schema.columns WHERE table_name = 'transactions' AND column_name = 'category'`
    )
    if (col.length) {
      const { rows: distinct } = await client.query(
        `SELECT DISTINCT instance_id, category, type FROM transactions WHERE category IS NOT NULL AND category != ''`
      )
      for (const row of distinct) {
        const { instance_id, category, type } = row
        const g = await client.query('SELECT id FROM categories WHERE instance_id IS NULL AND name = $1', [category])
        let gid
        if (g.rows.length) {
          gid = g.rows[0].id
        } else {
          const ins = await client.query(
            'INSERT INTO categories (name, type, is_default) VALUES ($1, $2, TRUE) RETURNING id',
            [category, type]
          )
          gid = ins.rows[0].id
        }
        if (instance_id === null) {
          await client.query(
            'UPDATE transactions SET category_id = $1 WHERE instance_id IS NULL AND category = $2',
            [gid, category]
          )
          continue
        }
        const cp = await client.query('SELECT id FROM categories WHERE instance_id = $1 AND name = $2', [instance_id, category])
        let copyId
        if (cp.rows.length) {
          copyId = cp.rows[0].id
        } else {
          const ins = await client.query(
            'INSERT INTO categories (name, type, instance_id, is_default) VALUES ($1, $2, $3, FALSE) RETURNING id',
            [category, type, instance_id]
          )
          copyId = ins.rows[0].id
        }
        await client.query(
          'UPDATE transactions SET category_id = $1 WHERE instance_id = $2 AND category = $3',
          [copyId, instance_id, category]
        )
      }

      await client.query(`UPDATE transactions SET category_id = NULL WHERE category IS NULL OR category = ''`)
    await client.query(`ALTER TABLE transactions DROP COLUMN IF EXISTS category`)
    await client.query(`DROP INDEX IF EXISTS idx_transactions_category`)
    }

    await client.query('COMMIT')
    console.log('Category migration complete')

  } catch (err) {
    await client.query('ROLLBACK')
    console.error('Category migration failed:', err.message)
  } finally {
    client.release()
  }
} catch (err) {
  console.error('Migration failed:', err.message)
} finally {
  await pool.end()
}
