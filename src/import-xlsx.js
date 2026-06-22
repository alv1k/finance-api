import { readFileSync } from 'fs'
import XLSX from 'xlsx'
import pool from './db.js'

const filePath = process.argv[2]
if (!filePath) {
  console.error('Usage: node src/import-xlsx.js <path-to-xlsx>')
  process.exit(1)
}

const wb = XLSX.read(readFileSync(filePath))
const data = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]])

console.log(`Importing ${data.length} records...`)

let imported = 0
for (const row of data) {
  try {
    await pool.query(
      `INSERT INTO transactions (id, name, date, price, quantity, amount, category, comment)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (id) DO NOTHING`,
      [
        row['ID'],
        row['Название'],
        row['Дата'],
        row['Цена'] || 0,
        row['Количество'] || 0,
        row['Сумма'] || 0,
        row['Классификация'] || '',
        row['Комментарий'] || '',
      ]
    )
    imported++
  } catch (err) {
    console.error(`Failed row ${row['ID']}:`, err.message)
  }
}

console.log(`Done: ${imported}/${data.length} records imported`)
await pool.end()
