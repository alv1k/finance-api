import pool from './db.js'
import XLSX from 'xlsx'
import { sendBackupEmail } from './mailer.js'

export async function generateAndSendUserBackup(userId, targetEmail = null) {
  const { rows: userRows } = await pool.query('SELECT id, username, email, backup_frequency FROM users WHERE id = $1', [userId])
  if (!userRows.length) throw new Error('Пользователь не найден')
  const user = userRows[0]
  const email = targetEmail || user.email
  if (!email) throw new Error('Email для отправки бэкапа не указан')

  // 1. Fetch user instances
  const { rows: instances } = await pool.query(
    `SELECT i.id, i.name, im.role
     FROM instances i
     JOIN instance_members im ON im.instance_id = i.id
     WHERE im.user_id = $1
     ORDER BY i.id ASC`,
    [userId]
  )

  const wb = XLSX.utils.book_new()
  let totalTxCount = 0
  let totalCatCount = 0
  let totalGoalCount = 0

  for (const inst of instances) {
    // A. Transactions
    const { rows: txs } = await pool.query(
      `SELECT t.id as "ID",
              to_char(t.date, 'YYYY-MM-DD') as "Дата",
              t.name as "Название",
              CASE
                WHEN t.type = 'expense' THEN 'Расход'
                WHEN t.type = 'income' THEN 'Доход'
                WHEN t.type = 'savings' THEN 'Накопление'
                ELSE t.type
              END as "Тип",
              COALESCE(c.name, '') as "Категория",
              t.amount as "Сумма (₽)",
              t.comment as "Комментарий"
       FROM transactions t
       LEFT JOIN categories c ON c.id = t.category_id
       WHERE t.instance_id = $1
       ORDER BY t.date DESC, t.id DESC`,
      [inst.id]
    )
    totalTxCount += txs.length
    const wsTx = XLSX.utils.json_to_sheet(txs.length ? txs : [{ 'Информация': 'Нет транзакций' }])
    const sheetNameTx = `${inst.name.slice(0, 20)}_Транзакции`.replace(/[:\\/?*\[\]]/g, '')
    XLSX.utils.book_append_sheet(wb, wsTx, sheetNameTx.slice(0, 31))

    // B. Categories
    const { rows: cats } = await pool.query(
      `SELECT name as "Категория",
              CASE
                WHEN type = 'expense' THEN 'Расход'
                WHEN type = 'income' THEN 'Доход'
                WHEN type = 'savings' THEN 'Накопление'
                ELSE type
              END as "Тип"
       FROM categories
       WHERE instance_id = $1 OR (instance_id IS NULL AND is_default = TRUE)
       ORDER BY type, name`,
      [inst.id]
    )
    totalCatCount += cats.length
    const wsCat = XLSX.utils.json_to_sheet(cats)
    const sheetNameCat = `${inst.name.slice(0, 20)}_Категории`.replace(/[:\\/?*\[\]]/g, '')
    XLSX.utils.book_append_sheet(wb, wsCat, sheetNameCat.slice(0, 31))

    // C. Savings Goals
    const { rows: goals } = await pool.query(
      `SELECT name as "Цель",
              target_amount as "Целевая сумма (₽)",
              current_amount as "Накоплено (₽)",
              to_char(target_date, 'YYYY-MM-DD') as "Срок",
              CASE WHEN is_completed THEN 'Да' ELSE 'Нет' END as "Выполнена",
              comment as "Комментарий"
       FROM savings_goals
       WHERE instance_id = $1
       ORDER BY id ASC`,
      [inst.id]
    )
    totalGoalCount += goals.length
    if (goals.length) {
      const wsGoals = XLSX.utils.json_to_sheet(goals)
      const sheetNameGoals = `${inst.name.slice(0, 20)}_Цели`.replace(/[:\\/?*\[\]]/g, '')
      XLSX.utils.book_append_sheet(wb, wsGoals, sheetNameGoals.slice(0, 31))
    }
  }

  // Summary sheet
  const summaryData = [
    { 'Параметр': 'Пользователь', 'Значение': user.username },
    { 'Параметр': 'Email для бэкапов', 'Значение': email },
    { 'Параметр': 'Частота бэкапов', 'Значение': user.backup_frequency || 'не настроена' },
    { 'Параметр': 'Дата формирования', 'Значение': new Date().toLocaleString('ru-RU') },
    { 'Параметр': 'Всего инстансов (бюджетов)', 'Значение': instances.length },
    { 'Параметр': 'Всего выгружено транзакций', 'Значение': totalTxCount },
    { 'Параметр': 'Всего категорий', 'Значение': totalCatCount },
    { 'Параметр': 'Всего целей накоплений', 'Значение': totalGoalCount }
  ]
  const wsSummary = XLSX.utils.json_to_sheet(summaryData)
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Сводка')

  const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' })
  const filename = `tiin_finance_backup_${new Date().toISOString().slice(0, 10)}.xlsx`

  const stats = {
    txCount: totalTxCount,
    catCount: totalCatCount,
    goalCount: totalGoalCount
  }

  const result = await sendBackupEmail(email, buffer, filename, stats)
  if (result.success) {
    await pool.query('UPDATE users SET last_backup_at = NOW() WHERE id = $1', [userId])
  }
  return { success: result.success, stats, filename }
}

export async function runScheduledBackups() {
  try {
    const { rows: users } = await pool.query(
      `SELECT id, username, email, backup_frequency, last_backup_at
       FROM users
       WHERE email IS NOT NULL AND backup_frequency IN ('weekly', 'monthly')`
    )

    const now = Date.now()
    for (const u of users) {
      try {
        const last = u.last_backup_at ? new Date(u.last_backup_at).getTime() : 0
        const diffDays = (now - last) / (1000 * 60 * 60 * 24)

        let shouldRun = false
        if (u.backup_frequency === 'weekly' && diffDays >= 7) {
          shouldRun = true
        } else if (u.backup_frequency === 'monthly' && diffDays >= 30) {
          shouldRun = true
        }

        if (shouldRun) {
          console.log(`[Scheduled Backup] Triggering backup for user ${u.username} (${u.email}) frequency=${u.backup_frequency}`)
          await generateAndSendUserBackup(u.id, u.email)
        }
      } catch (userErr) {
        console.error(`[Scheduled Backup Error] Failed for user ${u.id}:`, userErr.message)
      }
    }
  } catch (err) {
    console.error('[Scheduled Backup Error]', err.message)
  }
}
