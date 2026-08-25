import pool from './db.js'

export const PLANS = {
  free: {
    name: 'Free Тариф',
    code: 'free',
    badge: '🆓 Free',
    maxInstances: 1,
    maxTransactions: 150,
    monthlyReceiptScans: 10,
    monthlyAiAdvices: 0,
    maxMembers: 1,
    allowImportXlsx: false,
    allowAiAdvisor: false
  },
  pro: {
    name: 'PRO Личный',
    code: 'pro',
    badge: '⚡ PRO',
    maxInstances: 3,
    maxTransactions: Infinity,
    monthlyReceiptScans: 50,
    monthlyAiAdvices: 10,
    maxMembers: 1,
    allowImportXlsx: true,
    allowAiAdvisor: true
  },
  family: {
    name: 'Семья & Бизнес',
    code: 'family',
    badge: '👨‍👩‍👧‍👦 Family',
    maxInstances: 10,
    maxTransactions: Infinity,
    monthlyReceiptScans: 150,
    monthlyAiAdvices: 30,
    maxMembers: 5,
    allowImportXlsx: true,
    allowAiAdvisor: true
  }
}

/**
 * Get effective plan details for a given user.
 * If user is admin, they have unlimited quotas.
 */
export async function getUserPlanInfo(userId) {
  const { rows } = await pool.query(
    'SELECT id, username, is_admin, plan, plan_expires_at FROM users WHERE id = $1',
    [userId]
  )
  if (!rows.length) return null
  const user = rows[0]

  let planCode = user.plan || 'free'

  // If expired, fall back to free
  if (user.plan_expires_at && new Date(user.plan_expires_at) < new Date()) {
    planCode = 'free'
  }

  const basePlan = PLANS[planCode] || PLANS.free

  if (user.is_admin) {
    return {
      code: 'admin',
      name: 'Администратор (Unlimited)',
      badge: '👑 Admin',
      expires_at: null,
      is_admin: true,
      limits: {
        maxInstances: Infinity,
        maxTransactions: Infinity,
        monthlyReceiptScans: Infinity,
        monthlyAiAdvices: Infinity,
        maxMembers: Infinity,
        allowImportXlsx: true,
        allowAiAdvisor: true
      }
    }
  }

  return {
    code: basePlan.code,
    name: basePlan.name,
    badge: basePlan.badge,
    expires_at: user.plan_expires_at,
    is_admin: false,
    limits: { ...basePlan }
  }
}

/**
 * Get user usage statistics (instances, transactions, receipt scans this month, ai advices this month)
 */
export async function getUserUsage(userId, instanceId = null) {
  // Count owned instances
  const { rows: instRows } = await pool.query(
    `SELECT COUNT(*) FROM instance_members WHERE user_id = $1 AND role = 'owner'`,
    [userId]
  )
  const instancesCount = parseInt(instRows[0].count) || 0

  // Count transactions in specific instance if provided
  let instanceTransactionsCount = 0
  if (instanceId) {
    const { rows: txRows } = await pool.query(
      'SELECT COUNT(*) FROM transactions WHERE instance_id = $1',
      [instanceId]
    )
    instanceTransactionsCount = parseInt(txRows[0].count) || 0
  }

  // Count receipt scans in current month
  const { rows: scanRows } = await pool.query(
    `SELECT COUNT(*) FROM user_actions_log
     WHERE user_id = $1 AND action_type = 'scan_receipt'
       AND created_at >= date_trunc('month', CURRENT_DATE)`,
    [userId]
  )
  const receiptScansMonth = parseInt(scanRows[0].count) || 0

  // Count AI advices in current month
  const { rows: aiRows } = await pool.query(
    `SELECT COUNT(*) FROM user_actions_log
     WHERE user_id = $1 AND action_type = 'ai_advice'
       AND created_at >= date_trunc('month', CURRENT_DATE)`,
    [userId]
  )
  const aiAdvicesMonth = parseInt(aiRows[0].count) || 0

  return {
    instancesCount,
    instanceTransactionsCount,
    receiptScansMonth,
    aiAdvicesMonth
  }
}
