import pool from './db.js'

const statements = [
  `CREATE TABLE IF NOT EXISTS users (
    id         SERIAL PRIMARY KEY,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    is_admin   BOOLEAN DEFAULT FALSE,
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
  `CREATE INDEX IF NOT EXISTS idx_transactions_category ON transactions(category)`,
  `CREATE INDEX IF NOT EXISTS idx_transactions_instance_id ON transactions(instance_id)`,
  `CREATE INDEX IF NOT EXISTS idx_instance_members_user_id ON instance_members(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_instance_members_instance_id ON instance_members(instance_id)`,
  `CREATE INDEX IF NOT EXISTS idx_join_requests_instance_id ON join_requests(instance_id)`,

  `CREATE TABLE IF NOT EXISTS categories (
    id         SERIAL PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    type       TEXT NOT NULL CHECK (type IN ('expense', 'income', 'savings')),
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,

  `INSERT INTO categories (name, type) VALUES
    ('продукты', 'expense'),
    ('ЖКУ', 'expense'),
    ('автомобиль', 'expense'),
    ('здоровье', 'expense'),
    ('сладости', 'expense'),
    ('прочие нужды', 'expense'),
    ('развлечения', 'expense'),
    ('связь', 'expense'),
    ('подарки', 'expense'),
    ('одежда', 'expense'),
    ('питомцы', 'expense'),
    ('огород', 'expense'),
    ('хобби', 'expense'),
    ('готовая еда', 'expense'),
    ('доставка товаров', 'expense'),
    ('благотворительность', 'expense'),
    ('без классификации', 'expense'),
    ('проезд в автобусах', 'expense'),
    ('зп Айсен', 'income'),
    ('зп Алена', 'income'),
    ('такси', 'income'),
    ('другой доход', 'income')
  ON CONFLICT (name) DO NOTHING`,

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

  `INSERT INTO categories (name, type) VALUES ('накопления', 'savings') ON CONFLICT (name) DO NOTHING`,
  `INSERT INTO categories (name, type) VALUES ('кредиты', 'expense') ON CONFLICT (name) DO NOTHING`,

  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS goal_id INTEGER`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS savings_type TEXT DEFAULT 'free' CHECK (savings_type IN ('free', 'goal'))`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS is_planned BOOLEAN DEFAULT FALSE`,
  `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS planned_date DATE`,
  `CREATE INDEX IF NOT EXISTS idx_transactions_is_planned ON transactions(instance_id, is_planned, planned_date)`,

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
]

try {
  for (const sql of statements) {
    await pool.query(sql)
  }
  console.log('Migration complete')
} catch (err) {
  console.error('Migration failed:', err.message)
} finally {
  await pool.end()
}
