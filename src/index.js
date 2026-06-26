import express from 'express'
import cors from 'cors'
import path from 'path'
import { fileURLToPath } from 'url'
import pool from './db.js'
import {
  hashPassword, verifyPassword, signToken,
  authMiddleware, optionalAuthMiddleware, adminMiddleware, instanceMiddleware, instanceOwnerMiddleware
} from './auth.js'
import { getCookiesFromBrowser, doYandexLogin, isLoggedIn, refreshSessionIfNeeded } from './pkc-browser.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = process.env.PORT || 3000

app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname, '../public')))

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' })
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' })
    const passwordHash = await hashPassword(password)
    const { rows } = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, is_admin',
      [username, passwordHash]
    )
    const token = signToken({ id: rows[0].id, username: rows[0].username, is_admin: rows[0].is_admin })
    res.status(201).json({ user: rows[0], token })
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username already taken' })
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' })
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username])
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' })
    const valid = await verifyPassword(password, rows[0].password)
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' })
    const user = rows[0]
    const token = signToken({ id: user.id, username: user.username, is_admin: user.is_admin })
    res.json({ user: { id: user.id, username: user.username, is_admin: user.is_admin }, token })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, is_admin FROM users WHERE id = $1', [req.user.id]
    )
    if (!rows.length) return res.status(404).json({ error: 'User not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== INSTANCE ROUTES ====================

app.post('/api/instances', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body
    if (!name) return res.status(400).json({ error: 'Instance name required' })
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
    } finally {
      client.release()
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/instances', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT i.id, i.name, i.created_at, m.role
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
    if (!rows.length) return res.status(404).json({ error: 'Instance not found' })
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

// ==================== JOIN REQUEST ROUTES ====================

app.post('/api/instances/:instanceId/join', authMiddleware, async (req, res) => {
  try {
    const instanceId = parseInt(req.params.instanceId)
    const { rows: instCheck } = await pool.query('SELECT id FROM instances WHERE id = $1', [instanceId])
    if (!instCheck.length) return res.status(404).json({ error: 'Instance not found' })
    const { rows: memberCheck } = await pool.query(
      'SELECT 1 FROM instance_members WHERE instance_id = $1 AND user_id = $2',
      [instanceId, req.user.id]
    )
    if (memberCheck.length) return res.status(409).json({ error: 'Already a member' })
    const { rows: reqCheck } = await pool.query(
      "SELECT 1 FROM join_requests WHERE instance_id = $1 AND user_id = $2 AND status = 'pending'",
      [instanceId, req.user.id]
    )
    if (reqCheck.length) return res.status(409).json({ error: 'Request already pending' })
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
        return res.status(404).json({ error: 'Request not found or already resolved' })
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
    if (!rows.length) return res.status(404).json({ error: 'Request not found or already resolved' })
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
    if (userId === req.user.id) return res.status(400).json({ error: 'Cannot remove yourself. Delete the instance instead.' })
    const { rowCount } = await pool.query(
      "DELETE FROM instance_members WHERE instance_id = $1 AND user_id = $2 AND role != 'owner'",
      [req.instanceId, userId]
    )
    if (!rowCount) return res.status(404).json({ error: 'Member not found or is owner' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== TRANSACTION ROUTES (instance-scoped) ====================

app.get('/api/instances/:instanceId/transactions', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { category, exclude_category, type, exclude_type, is_planned, from, to, search, limit = 100, offset = 0 } = req.query
    const conditions = ['t.instance_id = $1']
    const params = [req.instanceId]
    let i = 2
    if (category) { conditions.push(`t.category = $${i++}`); params.push(category) }
    if (exclude_category) { conditions.push(`t.category != $${i++}`); params.push(exclude_category) }
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
      `SELECT t.* FROM transactions t ${where} ORDER BY t.date DESC, t.id LIMIT $${i++} OFFSET $${i++}`,
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
      'SELECT * FROM transactions WHERE id = $1 AND instance_id = $2',
      [req.params.id, req.instanceId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/instances/:instanceId/transactions', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { id, name, date, type, price, quantity, amount, category, comment, is_planned, planned_date } = req.body
    const { rows } = await pool.query(
      `INSERT INTO transactions (id, name, date, type, price, quantity, amount, category, comment, instance_id, is_planned, planned_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [id || crypto.randomUUID(), name, date, type || 'expense', price, quantity, amount, category, comment || '', req.instanceId, is_planned || false, planned_date || null]
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
    if (!rows.length) return res.status(404).json({ error: 'Planned expense not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/instances/:instanceId/transactions/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, date, type, price, quantity, amount, category, comment, is_planned, planned_date } = req.body
    const { rows } = await pool.query(
      `UPDATE transactions SET name=$1, date=$2, type=$3, price=$4, quantity=$5, amount=$6, category=$7, comment=$8, is_planned=$9, planned_date=$10
       WHERE id=$11 AND instance_id=$12 RETURNING *`,
      [name, date, type, price, quantity, amount, category, comment, is_planned || false, planned_date || null, req.params.id, req.instanceId]
    )
    if (!rows.length) return res.status(404).json({ error: 'Not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/transactions/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM transactions WHERE id = $1 AND instance_id = $2',
      [req.params.id, req.instanceId]
    )
    if (!rowCount) return res.status(404).json({ error: 'Not found' })
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
                        WHERE t.instance_id = sg.instance_id AND t.goal_id = sg.id AND t.type = 'savings'), 0) as saved
       FROM savings_goals sg
       WHERE sg.instance_id = $1
       ORDER BY sg.created_at DESC`,
      [req.instanceId]
    )

    const { rows: transactions } = await pool.query(
      `SELECT t.*, sg.name as goal_name
       FROM transactions t
       LEFT JOIN savings_goals sg ON sg.id = t.goal_id
       ${where_t}
       ORDER BY t.date DESC, t.id DESC`,
      params_t
    )

    const { rows: byMonth } = await pool.query(
      `SELECT TO_CHAR(t.date, 'YYYY-MM') as month, SUM(t.amount) as total, COUNT(*) as count
       FROM transactions t ${where_t} GROUP BY month ORDER BY month ASC`,
      params_t
    )

    const { rows: freeSummary } = await pool.query(
      `SELECT SUM(t.amount) as total FROM transactions t ${where_t} AND t.savings_type = 'free'`,
      params_t
    )

    const { rows: totalSummary } = await pool.query(
      `SELECT SUM(t.amount) as total FROM transactions t ${where_t}`,
      params_t
    )

    const freeTotal = parseFloat(freeSummary[0]?.total || 0)
    const totalSaved = parseFloat(totalSummary[0]?.total || 0)

    res.json({
      goals: goals.map(g => ({ ...g, saved: parseFloat(g.saved), target_amount: parseFloat(g.target_amount), current_amount: parseFloat(g.saved) })),
      transactions,
      byMonth: byMonth.map(r => ({ month: r.month, total: parseFloat(r.total), count: parseInt(r.count) })),
      freeTotal,
      totalSaved
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Assign free savings transaction(s) to a goal
app.post('/api/instances/:instanceId/savings/assign', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { transaction_ids, goal_id } = req.body
    if (!transaction_ids || !transaction_ids.length || !goal_id) {
      return res.status(400).json({ error: 'transaction_ids and goal_id required' })
    }
    const ids = transaction_ids.filter(id => id)
    if (!ids.length) return res.status(400).json({ error: 'No valid transaction ids' })

    const placeholders = ids.map((_, idx) => `$${idx + 3}`).join(',')
    await pool.query(
      `UPDATE transactions SET goal_id = $1, savings_type = 'goal'
       WHERE instance_id = $2 AND id IN (${placeholders}) AND type = 'savings'`,
      [goal_id, req.instanceId, ...ids]
    )
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Partially assign free savings to a goal
app.post('/api/instances/:instanceId/savings/assign-partial', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { assignments, goal_id } = req.body
    if (!assignments || !assignments.length || !goal_id) {
      return res.status(400).json({ error: 'assignments and goal_id required' })
    }

    for (const a of assignments) {
      if (!a.tx_id || !a.amount || a.amount <= 0) continue

      // Get original transaction
      const { rows: orig } = await pool.query(
        "SELECT * FROM transactions WHERE id = $1 AND instance_id = $2 AND type = 'savings' AND (savings_type = 'free' OR savings_type IS NULL)",
        [String(a.tx_id), req.instanceId]
      )
      if (!orig.length) continue
      const tx = orig[0]

      const assignAmount = parseFloat(a.amount)
      const currentAmount = parseFloat(tx.amount)
      if (assignAmount > currentAmount) {
        return res.status(400).json({ error: 'Assign amount exceeds transaction amount for tx ' + a.tx_id })
      }

      if (assignAmount === currentAmount) {
        // Full amount — just update the original
        await pool.query(
          "UPDATE transactions SET goal_id = $1, savings_type = 'goal' WHERE id = $2",
          [goal_id, String(a.tx_id)]
        )
      } else {
        // Partial — create new goal tx, reduce original
        const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
        await pool.query(
          `INSERT INTO transactions (id, name, date, type, amount, category, comment, instance_id, goal_id, savings_type)
           VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, 'goal')`,
          [newId, tx.name + ' (часть)', tx.date, assignAmount, tx.category, tx.comment || '', req.instanceId, goal_id]
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

// Transfer savings between goals or to free
app.post('/api/instances/:instanceId/savings/transfer', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { from_goal_id, to_goal_id, to: toTarget, amount } = req.body
    if (!from_goal_id || !amount || amount <= 0) {
      return res.status(400).json({ error: 'from_goal_id and amount required' })
    }
    if (toTarget !== 'free' && !to_goal_id) {
      return res.status(400).json({ error: 'destination required' })
    }

    // Get source goal
    const { rows: goalRows } = await pool.query(
      'SELECT * FROM savings_goals WHERE id = $1 AND instance_id = $2',
      [from_goal_id, req.instanceId]
    )
    if (!goalRows.length) return res.status(404).json({ error: 'Goal not found' })
    const goal = goalRows[0]

    // Calculate current saved amount
    const { rows: savedRows } = await pool.query(
      "SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE instance_id = $1 AND goal_id = $2 AND type = 'savings'",
      [req.instanceId, from_goal_id]
    )
    const savedTotal = parseFloat(savedRows[0].total)
    if (amount > savedTotal) {
      return res.status(400).json({ error: 'Amount exceeds saved total' })
    }

    // Get transactions for this goal (most recent first to partially move)
    const { rows: txRows } = await pool.query(
      "SELECT * FROM transactions WHERE instance_id = $1 AND goal_id = $2 AND type = 'savings' ORDER BY date DESC, id DESC",
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
          await pool.query("UPDATE transactions SET goal_id = NULL, savings_type = 'free' WHERE id = $1", [tx.id])
        } else {
          await pool.query('UPDATE transactions SET goal_id = $1, savings_type = $goal WHERE id = $2', [to_goal_id, tx.id])
        }
      } else {
        // Partial — create new tx, reduce original
        const newId = 'sav-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
        const newSavingsType = toTarget === 'free' ? 'free' : 'goal'
        const newGoalId = toTarget === 'free' ? null : to_goal_id
        await pool.query(
          "INSERT INTO transactions (id, name, date, type, amount, category, comment, instance_id, goal_id, savings_type) VALUES ($1, $2, $3, 'savings', $4, $5, $6, $7, $8, $9)",
          [newId, tx.name + ' (перевод)', tx.date, moveAmount, tx.category, tx.comment || '', req.instanceId, newGoalId, newSavingsType]
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

app.post('/api/instances/:instanceId/savings', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, target_amount, target_date, comment } = req.body
    if (!name || !target_amount) return res.status(400).json({ error: 'Name and target amount required' })
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
    if (!rows.length) return res.status(404).json({ error: 'Not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/instances/:instanceId/savings/:id', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM savings_goals WHERE id = $1 AND instance_id = $2',
      [req.params.id, req.instanceId]
    )
    if (!rowCount) return res.status(404).json({ error: 'Not found' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
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
    const { name, lender, total_amount, interest_rate, monthly_payment, start_date, end_date, comment } = req.body
    if (!name || !total_amount) return res.status(400).json({ error: 'Name and total amount required' })
    const remaining = total_amount
    const { rows } = await pool.query(
      `INSERT INTO credits (name, instance_id, lender, total_amount, interest_rate, monthly_payment, start_date, end_date, remaining_amount, comment)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [name, req.instanceId, lender || '', parseFloat(total_amount), parseFloat(interest_rate) || 0, parseFloat(monthly_payment) || 0, start_date || null, end_date || null, remaining, comment || '']
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/instances/:instanceId/credits/:creditId', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name, lender, total_amount, interest_rate, monthly_payment, start_date, end_date, comment } = req.body
    if (!name) return res.status(400).json({ error: 'Name required' })
    const { rows } = await pool.query(
      `UPDATE credits SET name=$1, lender=$2, total_amount=$3, interest_rate=$4, monthly_payment=$5, start_date=$6, end_date=$7, comment=$8
       WHERE id=$9 AND instance_id=$10 RETURNING *`,
      [name, lender || '', parseFloat(total_amount) || 0, parseFloat(interest_rate) || 0, parseFloat(monthly_payment) || 0, start_date || null, end_date || null, comment || '', req.params.creditId, req.instanceId]
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

    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      const principal = parseFloat(principal_amount) || 0
      const interest = parseFloat(interest_amount) || 0

      const { rows } = await client.query(
        `INSERT INTO credit_payments (credit_id, amount, principal_amount, interest_amount, payment_date, comment, payment_type, early_strategy)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
        [req.params.creditId, parseFloat(amount), principal, interest, payment_date, comment || '', isEarly ? 'early' : 'regular', isEarly ? (early_strategy || 'reduce_term') : null]
      )

      await client.query(
        'UPDATE credits SET remaining_amount = GREATEST(COALESCE(remaining_amount, total_amount) - $1, 0) WHERE id = $2',
        [principal || parseFloat(amount), req.params.creditId]
      )

      if (create_transaction) {
        const { rows: creditRows } = await client.query('SELECT name FROM credits WHERE id = $1', [req.params.creditId])
        const creditName = creditRows[0]?.name || 'Кредит'
        const txId = 'tx-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
        await client.query(
          `INSERT INTO transactions (id, name, date, type, amount, category, comment, instance_id)
           VALUES ($1, $2, $3, 'expense', $4, 'кредиты', $5, $6)`,
          [txId, 'Платёж по кредиту: ' + creditName, payment_date, parseFloat(amount), `Основной долг: ${principal.toFixed(2)}, Проценты: ${interest.toFixed(2)}`, req.instanceId]
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

app.get('/api/instances/:instanceId/categories', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { from, to, category, type } = req.query
    const conditions = ['instance_id = $1']
    const params = [req.instanceId]
    let i = 2
    if (from) { conditions.push(`date >= $${i++}`); params.push(from) }
    if (to) { conditions.push(`date <= $${i++}`); params.push(to) }
    if (category) { conditions.push(`category = $${i++}`); params.push(category) }
    if (type) { conditions.push(`type = $${i++}`); params.push(type) }
    const where = `WHERE ${conditions.join(' AND ')}`
    const { rows } = await pool.query(
      `SELECT category, type, COUNT(*) as count, SUM(amount) as total
       FROM transactions ${where} GROUP BY category, type ORDER BY total DESC`,
      params
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== SUMMARY (instance-scoped) ====================

app.get('/api/instances/:instanceId/summary', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { from, to, category } = req.query
    const conditions = ['instance_id = $1']
    const params = [req.instanceId]
    let i = 2
    if (from) { conditions.push(`date >= $${i++}`); params.push(from) }
    if (to) { conditions.push(`date <= $${i++}`); params.push(to) }
    if (category) { conditions.push(`category = $${i++}`); params.push(category) }
    const where = `WHERE ${conditions.join(' AND ')}`
    const { rows } = await pool.query(
      `SELECT TO_CHAR(date, 'YYYY-MM') as month, category, COUNT(*) as count, SUM(amount) as total
       FROM transactions ${where} GROUP BY month, category ORDER BY month DESC, total DESC`,
      params
    )
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== SUGGEST CATEGORY (instance-scoped) ====================

app.get('/api/instances/:instanceId/suggest-category', authMiddleware, instanceMiddleware, async (req, res) => {
  try {
    const { name } = req.query
    if (!name) return res.json({ category: '', confidence: 0 })
    const words = String(name).trim().split(/\s+/).filter((w) => w.length >= 2)
    if (!words.length) return res.json({ category: '', confidence: 0 })
    const conditions = words.map((_, i) => `name ILIKE $${i + 2}`)
    const params = [req.instanceId, ...words.map((w) => `%${w}%`)]
    const { rows } = await pool.query(
      `SELECT category, COUNT(*) as cnt
       FROM transactions
       WHERE instance_id = $1 AND (${conditions.join(' OR ')}) AND category != ''
       GROUP BY category ORDER BY cnt DESC LIMIT 3`,
      params
    )
    if (!rows.length) return res.json({ category: '', confidence: 0 })
    const total = rows.reduce((s, r) => s + parseInt(r.cnt), 0)
    const best = rows[0]
    const confidence = Math.min(Math.round((parseInt(best.cnt) / total) * 100), 100)
    res.json({
      category: best.category,
      confidence: confidence,
      alternatives: rows.slice(1).map(r => ({ category: r.category, confidence: Math.round((parseInt(r.cnt) / total) * 100) }))
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== PROVERKACHEKA SESSIONS & PROXY ====================

const pkcSessions = new Map()

app.post('/api/pkc-proxy', async (req, res) => {
  try {
    const { fn, fd, fp, n, s, t } = req.body
    const cookies = req.headers['x-pkc-cookies']
    if (!cookies) return res.status(400).json({ error: 'No cookies provided' })
    if (!fn || !fd || !fp) return res.status(400).json({ error: 'Missing fn, fd, fp' })

    let tokenD = 1234
    const base = fn + String(fd) + String(fp) + String(n || 1) + (s || '') + (t || '') + '1'
    for (let d = 0; d < 10000; d++) {
      const hash = String(base + d).split('').reduce((a, c) => ((a << 5) - a + c.charCodeAt(0)) | 0, 0)
      const zeros = String(hash).split('0').length - 1
      if (zeros > 4) { tokenD = d; break }
    }

    const body = new URLSearchParams()
    body.append('fn', fn)
    body.append('fd', String(fd))
    body.append('fp', String(fp))
    body.append('n', String(n || 1))
    body.append('s', s || '')
    body.append('t', t || '')
    body.append('qr', '1')
    body.append('token', '0.' + tokenD)
    body.append('status', '')

    const res2 = await fetch('https://proverkacheka.com/api/v1/check/get', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://proverkacheka.com',
        'Referer': 'https://proverkacheka.com/',
        'Cookie': cookies
      },
      body: body.toString(),
      signal: AbortSignal.timeout(15000)
    })

    const data = await res2.json()
    res.json(data)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

function getPkcSession(userId) {
  const s = pkcSessions.get(userId)
  if (s && s.expiresAt > Date.now()) return s
  pkcSessions.delete(userId)
  return null
}

function setPkcSession(userId, cookies) {
  pkcSessions.set(userId, { cookies, expiresAt: Date.now() + 24 * 3600 * 1000 })
}

function buildCookieHeader(cookies) {
  if (typeof cookies === 'string') {
    return cookies.split(';').map(c => c.trim()).filter(c => c).map(c => {
      const m = c.match(/^([^=]+)=(.+)/)
      if (!m) return null
      const k = m[1].trim()
      const v = m[2].trim().replace(/[^\x00-\x7F]/g, '')
      return `${k}=${v}`
    }).filter(Boolean).join('; ')
  }
  return Object.entries(cookies).map(([k, v]) => `${k}=${String(v).replace(/[^\x00-\x7F]/g, '')}`).join('; ')
}

async function fetchReceiptFromPkc(fn, fd, fp, n, sum, datetime, cookies) {
  const t = datetime || ''
  const s = sum ? String(sum) : ''

  let tokenD = 1234
  const base = fn + String(fd) + String(fp) + String(n) + s + t + '1'
  for (let d = 0; d < 10000; d++) {
    const hash = String(base + d).split('').reduce((a, c) => ((a << 5) - a + c.charCodeAt(0)) | 0, 0)
    const zeros = String(hash).split('0').length - 1
    if (zeros > 4) { tokenD = d; break }
  }

  const body = new URLSearchParams()
  body.append('fn', fn)
  body.append('fd', String(fd))
  body.append('fp', String(fp))
  body.append('n', String(n || 1))
  body.append('s', s)
  body.append('t', t)
  body.append('qr', '1')
  body.append('token', '0.' + tokenD)
  body.append('status', '')

  const cookieHeader = cookies ? buildCookieHeader(cookies) : ''

  const res = await fetch('https://proverkacheka.com/api/v1/check/get', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': 'https://proverkacheka.com',
      'Referer': 'https://proverkacheka.com/',
      ...(cookieHeader ? { 'Cookie': cookieHeader } : {})
    },
    body: body.toString(),
    signal: AbortSignal.timeout(15000)
  })

  if (!res.ok) return null
  const data = await res.json()

  if (data.code !== 1 || !data.data) return null

  const json = data.data.json
  if (!json) return null

  const result = {
    seller: json.user || '',
    seller_inn: json.userInn || '',
    items: []
  }

  if (json.items && Array.isArray(json.items)) {
    for (const item of json.items) {
      const name = item.name || ''
      const price = parseFloat(item.price) / 100
      const qty = parseFloat(item.quantity) || 1
      const sumItem = parseFloat(item.sum) / 100
      if (name) {
        result.items.push({ name, price, quantity: qty, amount: sumItem || (price * qty) })
      }
    }
  }

  return result
}

// ==================== YANDEX OAUTH ====================

app.get('/api/yandex/auth-url', authMiddleware, (req, res) => {
  const state = crypto.randomUUID()
  const userId = req.user.id
  pkcSessions.set(userId + '_state', { state, expiresAt: Date.now() + 600000 })
  const url = `https://oauth.yandex.ru/authorize?response_type=code&client_id=${process.env.YANDEX_OAUTH_ID}&state=${state}&redirect_uri=https://oauth.yandex.ru/verification_code`
  res.json({ url, state })
})

app.post('/api/yandex/code', authMiddleware, async (req, res) => {
  try {
    const { code, state } = req.body
    if (!code || !state) return res.status(400).json({ error: 'code and state required' })

    const userId = req.user.id
    const stored = pkcSessions.get(userId + '_state')
    if (!stored || stored.expiresAt < Date.now() || stored.state !== state) {
      return res.status(400).json({ error: 'Invalid or expired state' })
    }
    pkcSessions.delete(userId + '_state')

    const tokenRes = await fetch('https://oauth.yandex.ru/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.YANDEX_OAUTH_ID,
        client_secret: process.env.YANDEX_OAUTH_SECRET,
        redirect_uri: 'https://oauth.yandex.ru/verification_code'
      })
    })

    if (!tokenRes.ok) {
      const errText = await tokenRes.text()
      console.log('Yandex token error:', errText)
      return res.status(400).json({ error: 'Failed to get Yandex token: ' + errText })
    }

    const tokenData = await tokenRes.json()
    const accessToken = tokenData.access_token
    if (!accessToken) return res.status(400).json({ error: 'No access token from Yandex' })

    const passportCookies = {}
    const passportRes = await fetch('https://passport.yandex.ru/auth', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': `OAuth=${accessToken}`
      },
      body: new URLSearchParams({ from: 'proverkacheka' }),
      signal: AbortSignal.timeout(10000),
      redirect: 'manual'
    })

    const setCookieHeaders = passportRes.headers.raw ? passportRes.headers.raw()['set-cookie'] : []
    if (Array.isArray(setCookieHeaders)) {
      for (const sc of setCookieHeaders) {
        const match = sc.match(/^([^=]+)=([^;]+)/)
        if (match) passportCookies[match[1].trim()] = match[2].trim()
      }
    }

    if (Object.keys(passportCookies).length === 0) {
      const body = await passportRes.text()
      console.log('Passport status:', passportRes.status, 'body:', body.substring(0, 300))
      return res.status(400).json({ error: 'No session cookies from Yandex passport' })
    }

    setPkcSession(userId, passportCookies)
    console.log('PKC session saved for user', userId, 'cookies:', Object.keys(passportCookies))
    res.json({ success: true })
  } catch (err) {
    console.log('Yandex code error:', err.message)
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/yandex/session', authMiddleware, (req, res) => {
  const session = getPkcSession(req.user.id)
  res.json({ active: !!session })
})

// ==================== BROWSER-BASED PKC AUTH ====================

app.get('/api/pkc-browser/status', authMiddleware, async (req, res) => {
  try {
    const loggedIn = await isLoggedIn()
    const session = getPkcSession(req.user.id)
    res.json({
      browserLoggedIn: loggedIn,
      sessionActive: !!session,
      needsAuth: !loggedIn && !session
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/pkc-browser/init', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id
    const session = getPkcSession(userId)
    if (session) {
      const cookieStr = buildCookieHeader(session.cookies)
      const testData = await fetchReceiptFromPkc('test', 'test', 'test', 1, 0, '', cookieStr)
      if (testData !== null || session) {
        res.json({ success: true, message: 'Session already active' })
        return
      }
    }

    const state = crypto.randomUUID()
    pkcSessions.set(userId + '_pkc_init', { state, expiresAt: Date.now() + 120000 })
    const yandexUrl = `https://oauth.yandex.ru/authorize?response_type=code&client_id=${process.env.YANDEX_OAUTH_ID}&state=${state}&redirect_uri=https://oauth.yandex.ru/verification_code`

    res.json({
      success: true,
      loginUrl: yandexUrl,
      message: 'Откройте URL, войдите в Яндекс, и вы будете перенаправлены на proverkacheka.com'
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/pkc-browser/complete', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id
    const { state } = req.body

    const stored = pkcSessions.get(userId + '_pkc_init')
    if (!stored || stored.expiresAt < Date.now() || stored.state !== state) {
      return res.status(400).json({ error: 'Invalid or expired init session' })
    }
    pkcSessions.delete(userId + '_pkc_init')

    const result = await doYandexLogin('https://oauth.yandex.ru/authorize?response_type=code&client_id=' + process.env.YANDEX_OAUTH_ID + '&redirect_uri=https://oauth.yandex.ru/verification_code')

    if (result.success && result.cookies) {
      const cookieObj = {}
      result.cookies.split(';').forEach(pair => {
        const m = pair.trim().match(/^([^=]+)=(.+)/)
        if (m) cookieObj[m[1].trim()] = m[2].trim()
      })
      setPkcSession(userId, cookieObj)
      res.json({ success: true, message: 'Авторизация успешна' })
    } else {
      res.status(400).json({ success: false, error: result.error || 'Login failed' })
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/pkc-browser/refresh', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id
    const result = await refreshSessionIfNeeded(
      userId,
      getPkcSession,
      setPkcSession
    )
    if (result.refreshed) {
      res.json({ success: true, message: 'Сессия обновлена' })
    } else {
      res.json({ success: false, needsAuth: true, message: 'Требуется повторная авторизация' })
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ==================== FETCH RECEIPT BY QR CODE (instance-scoped) ====================

app.post('/api/instances/:instanceId/fetch-receipt', async (req, res) => {
  try {
    const { qr_string, cookies } = req.body
    if (!qr_string || !qr_string.trim()) return res.status(400).json({ error: 'QR string required' })

    const params = new URLSearchParams(qr_string.trim())
    const t = params.get('t')
    const s = params.get('s')
    const fn = params.get('fn')
    const i = params.get('i')
    const fp = params.get('fp')
    const n = params.get('n')

    if (!fn || !i || !fp) {
      return res.status(400).json({ error: 'Invalid QR code: missing required fields (fn, i, fp)' })
    }

    let receiptDate = new Date().toISOString().slice(0, 10)
    if (t) {
      const year = t.slice(0, 4)
      const month = t.slice(4, 6)
      const day = t.slice(6, 8)
      if (year && month && day) {
        receiptDate = `${year}-${month}-${day}`
      }
    }

    let totalSum = 0
    if (s) {
      const parsed = parseFloat(s)
      totalSum = parsed > 10000 ? parsed / 100 : parsed
    }

    const authHeader = req.headers.authorization
    let userId = null
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const payload = verifyToken(authHeader.slice(7))
        userId = payload.id
      } catch {}
    }

    let session = userId ? getPkcSession(userId) : null
    let cookiesHeader = cookies || (session ? session.cookies ? buildCookieHeader(session.cookies) : '' : '')

    if (!cookiesHeader) {
      return res.json({
        auth_required: true,
        _qr: qr_string,
        message: 'Для проверки чеков необходима авторизация на proverkacheka.com. Откройте сайт, войдите через Яндекс, скопируйте куки и вставьте в форму.'
      })
    }

    let pkcData = await fetchReceiptFromPkc(fn, i, fp, n, totalSum, t, cookiesHeader)

    if (!pkcData && userId) {
      const refreshed = await refreshSessionIfNeeded(userId, getPkcSession, setPkcSession)
      if (refreshed.refreshed) {
        const newSession = getPkcSession(userId)
        cookiesHeader = buildCookieHeader(newSession.cookies)
        pkcData = await fetchReceiptFromPkc(fn, i, fp, n, totalSum, t, cookiesHeader)
      }
    }

    if (!pkcData) {
      if (userId) pkcSessions.delete(userId)
      return res.json({
        auth_required: true,
        _qr: qr_string,
        message: 'Сессия истекла или невалидна. Пожалуйста, обновите куки.'
      })
    }

    if (userId && cookies) {
      const cookieObj = {}
      cookies.split(';').forEach(pair => {
        const m = pair.trim().match(/^([^=]+)=(.+)/)
        if (m) cookieObj[m[1].trim()] = m[2].trim().replace(/[^\x20-\x7E]/g, '')
      })
      setPkcSession(userId, cookieObj)
    }

    let items = pkcData.items
    if (!items.length && totalSum > 0) {
      items.push({ name: 'Покупка по чеку', price: totalSum, quantity: 1, amount: totalSum })
    }

    res.json({
      date: receiptDate,
      total: totalSum,
      seller: pkcData.seller,
      seller_inn: pkcData.seller_inn,
      items,
      raw: { fn, i, fp, n, t, s }
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
    const conditions = []
    const params = []
    let i = 1
    if (type) { conditions.push(`type = $${i++}`); params.push(type) }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''
    const { rows } = await pool.query(
      `SELECT id, name, type FROM categories ${where} ORDER BY type, name`,
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
    const { rows } = await pool.query(
      'INSERT INTO categories (name, type) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET type = $2 RETURNING *',
      [name, type]
    )
    res.status(201).json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/categories/:id', authMiddleware, async (req, res) => {
  try {
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

    const conditions = ['instance_id = $1']
    const params = [req.instanceId]
    let i = 2
    if (fromDate) { conditions.push(`date >= $${i++}`); params.push(fromDate) }
    if (toDate) { conditions.push(`date < $${i++}`); params.push(toDate) }
    const where = `WHERE ${conditions.join(' AND ')}`

    const { rows: totals } = await pool.query(
      `SELECT type, SUM(amount) as total, COUNT(*) as count
       FROM transactions ${where} GROUP BY type`,
      params
    )

    const { rows: byCategory } = await pool.query(
      `SELECT type, category, SUM(amount) as total, COUNT(*) as count
       FROM transactions ${where} AND category != '' GROUP BY type, category ORDER BY type, total DESC`,
      params
    )

    const { rows: byMonth } = await pool.query(
      `SELECT TO_CHAR(date, 'YYYY-MM') as month, type, SUM(amount) as total, COUNT(*) as count
       FROM transactions ${where} GROUP BY month, type ORDER BY month ASC`,
      params
    )

    const { rows: recent } = await pool.query(
      `SELECT * FROM transactions ${where} ORDER BY date DESC, id DESC LIMIT 10`,
      params
    )

    const expenseTotal = totals.find(t => t.type === 'expense')?.total || 0
    const incomeTotal = totals.find(t => t.type === 'income')?.total || 0

    res.json({
      period: { from: fromDate, to: toDate, period: period || 'month', year: y, month: month ? parseInt(month) : curMonth, quarter: quarter ? parseInt(quarter) : Math.ceil(curMonth / 3) },
      summary: {
        expense: { total: parseFloat(expenseTotal), count: parseInt(totals.find(t => t.type === 'expense')?.count || 0) },
        income: { total: parseFloat(incomeTotal), count: parseInt(totals.find(t => t.type === 'income')?.count || 0) },
        balance: parseFloat(incomeTotal) - parseFloat(expenseTotal)
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
      'SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC'
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
      'UPDATE users SET is_admin = $1 WHERE id = $2 RETURNING id, username, is_admin',
      [is_admin, userId]
    )
    if (!rows.length) return res.status(404).json({ error: 'User not found' })
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

// ==================== ADMIN PANEL UI ====================

app.get('/admin', (req, res) => {
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

app.listen(PORT, () => {
  console.log(`Finance API running on port ${PORT}`)
})
