// Telegram Bot Module for TIIN Finance
// Handles commands, photo receipt parsing via Gemini Vision 2.5 Flash, and quick expense creation

import pool from './db.js'
import { signToken } from './auth.js'

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN
const GEMINI_API_KEY = process.env.GEMINI_API_KEY
const BASE_URL = 'https://finance.tiinservice.online'

async function getAuthUrlForTgUser(tgId, instanceId = null) {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.is_admin, tfi.instance_id
       FROM telegram_finance_instances tfi
       JOIN instances i ON i.id = tfi.instance_id
       JOIN users u ON u.id = i.owner_id
       WHERE tfi.tg_id = $1`,
      [tgId]
    )
    if (rows.length) {
      const u = rows[0]
      const token = signToken({ id: u.id, username: u.username, is_admin: u.is_admin })
      const targetInst = instanceId || u.instance_id
      return `${BASE_URL}?auth_token=${encodeURIComponent(token)}&inst=${targetInst}`
    }
  } catch (err) {
    console.error('[Bot Auth URL Error]', err)
  }
  return BASE_URL
}

let offset = 0
let isPolling = false

export function startBot() {
  if (!BOT_TOKEN) {
    console.log('[Telegram Bot] BOT_TOKEN missing, skipping bot startup')
    return
  }
  console.log('[Telegram Bot] Starting bot polling loop for @FinanceTiinServiceBot...')
  isPolling = true
  pollUpdates()
}

async function pollUpdates() {
  while (isPolling) {
    try {
      const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getUpdates?offset=${offset}&timeout=30`, {
        signal: AbortSignal.timeout(35000)
      })
      if (!res.ok) {
        await new Promise(r => setTimeout(r, 5000))
        continue
      }
      const data = await res.json()
      if (data.ok && Array.isArray(data.result)) {
        for (const update of data.result) {
          offset = update.update_id + 1
          handleUpdate(update).catch(err => console.error('[Bot Error]', err))
        }
      }
    } catch (err) {
      if (err.name !== 'TimeoutError' && err.name !== 'AbortError') {
        console.error('[Bot Polling Error]', err.message)
      }
      await new Promise(r => setTimeout(r, 3000))
    }
  }
}

async function sendTelegramMessage(chatId, text, extra = {}) {
  try {
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'Markdown',
        ...extra
      })
    })
  } catch (err) {
    console.error('[Bot Send Error]', err.message)
  }
}

async function handleUpdate(update) {
  const msg = update.message
  if (!msg) return

  const chatId = msg.chat.id
  const tgId = msg.from?.id

  if (!tgId) return

  // 1. Handle /start command & deep linking (/start link_123)
  if (msg.text && msg.text.startsWith('/start')) {
    const parts = msg.text.split(' ')
    if (parts.length > 1 && parts[1].startsWith('link_')) {
      const targetInstanceId = parseInt(parts[1].replace('link_', ''))
      if (targetInstanceId > 0) {
        try {
          const { rows: inst } = await pool.query('SELECT name FROM instances WHERE id = $1', [targetInstanceId])
          if (inst.length) {
            await pool.query(
              `INSERT INTO telegram_finance_instances (tg_id, instance_id)
               VALUES ($1, $2)
               ON CONFLICT (tg_id) DO UPDATE SET instance_id = excluded.instance_id`,
              [tgId, targetInstanceId]
            )

            const webAppUrl = await getAuthUrlForTgUser(tgId, targetInstanceId)
            const linkSuccessMsg = `🔗 *Успешно привязано!*\n\n` +
              `Ваш Telegram теперь привязан к инстансу *«${inst[0].name}»*.\n\n` +
              `📸 Отправляйте фото чеков или пишите расходы прямо сюда в чат — они моментально появятся в вашем бюджете!`

            return sendTelegramMessage(chatId, linkSuccessMsg, {
              reply_markup: {
                inline_keyboard: [
                  [{ text: '💰 Открыть TIIN Finance', web_app: { url: webAppUrl } }]
                ]
              }
            })
          }
        } catch (err) {
          console.error('[Bot Link Error]', err)
        }
      }
    }

    const webAppUrl = await getAuthUrlForTgUser(tgId)
    const welcomeMsg = `👋 *Добро пожаловать в TIIN Finance!*\n\n` +
      `Я ваш персональный финансовый помощник.\n\n` +
      `📸 *Отправьте мне фото чека* из магазина — я сам распознаю товары, цены и категории и добавлю расход в ваш бюджет!\n\n` +
      `✍️ *Или напишите текстом*, например:\n` +
      `• \`Кофе 250\`\n` +
      `• \`Продукты 1450 супермаркет\`\n\n` +
      `📱 Нажмите кнопку ниже, чтобы открыть наглядный WebApp-интерфейс!`

    return sendTelegramMessage(chatId, welcomeMsg, {
      reply_markup: {
        inline_keyboard: [
          [{ text: '💰 Открыть TIIN Finance', web_app: { url: webAppUrl } }]
        ]
      }
    })
  }


  // Find user's linked instance or default primary instance
  const instanceId = await getUserInstanceId(tgId)

  // 2. Handle Photo (Receipt Image)
  if (msg.photo && msg.photo.length > 0) {
    await sendTelegramMessage(chatId, '⏳ *Анализирую чек с помощью нейросети Gemini AI...*')
    
    // Get highest resolution photo file_id
    const photo = msg.photo[msg.photo.length - 1]
    const fileId = photo.file_id

    const fileRes = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getFile?file_id=${fileId}`)
    const fileData = await fileRes.json()
    
    if (!fileData.ok || !fileData.result?.file_path) {
      return sendTelegramMessage(chatId, '❌ Не удалось загрузить фото чека. Попробуйте еще раз.')
    }

    const filePath = fileData.result.file_path
    const imgRes = await fetch(`https://api.telegram.org/file/bot${BOT_TOKEN}/${filePath}`)
    const arrayBuffer = await imgRes.arrayBuffer()
    const base64Image = Buffer.from(arrayBuffer).toString('base64')
    const mimeType = 'image/jpeg'

    // Fetch instance categories to pass to Gemini
    const existingCats = await getInstanceCategories(instanceId, 'expense')

function normalizeReceiptDate(rawDate) {
  if (!rawDate || typeof rawDate !== 'string') return null
  const clean = rawDate.trim()
  
  // YYYY-MM-DD or YYYY.MM.DD or YYYY/MM/DD
  const isoMatch = clean.match(/^(\d{4})[-./](\d{1,2})[-./](\d{1,2})/)
  if (isoMatch) {
    const y = parseInt(isoMatch[1], 10)
    const m = parseInt(isoMatch[2], 10)
    const d = parseInt(isoMatch[3], 10)
    if (m >= 1 && m <= 12 && d >= 1 && d <= 31) {
      return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`
    }
  }

  // DD.MM.YYYY or DD/MM/YYYY or DD-MM-YYYY
  const ruMatch = clean.match(/^(\d{1,2})[-./](\d{1,2})[-./](\d{4})/)
  if (ruMatch) {
    const d = parseInt(ruMatch[1], 10)
    const m = parseInt(ruMatch[2], 10)
    const y = parseInt(ruMatch[3], 10)
    if (m >= 1 && m <= 12 && d >= 1 && d <= 31) {
      return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`
    }
  }

  return null
}

    // Process image with Gemini 2.5 Flash Vision using instance categories
    const parsedReceipt = await parseReceiptImageWithGemini(base64Image, mimeType, existingCats)

    if (!parsedReceipt || !parsedReceipt.items || parsedReceipt.items.length === 0) {
      return sendTelegramMessage(chatId, '⚠️ Не удалось разобрать товары на чеке. Убедитесь, что фото четкое и чек хорошо виден.')
    }

    // Check for duplicate receipt items
    const receiptDate = normalizeReceiptDate(parsedReceipt.date)

    const validItems = []
    for (const item of parsedReceipt.items) {
      const price = parseFloat(item.price) || 0
      const qty = parseFloat(item.quantity) || 1
      let amount = parseFloat(item.amount) || 0

      // If amount is not provided or <= 0, calculate from price * quantity
      if (amount <= 0 && price > 0) {
        amount = Math.round(price * qty * 100) / 100
      }

      // If price was not provided or 0, calculate unit price from amount / quantity
      const unitPrice = price > 0 ? price : (qty > 0 ? Math.round((amount / qty) * 100) / 100 : amount)

      if (amount <= 0) continue

      const itemName = item.name || 'Товар по чеку'
      const catName = item.category || 'продукты'
      validItems.push({ item, price: unitPrice, qty, amount, itemName, catName })
    }

    if (validItems.length === 0) {
      return sendTelegramMessage(chatId, '⚠️ Не удалось разобрать товары на чеке. Убедитесь, что фото четкое и чек хорошо виден.')
    }

    // Check if duplicate transactions were already added for this instance
    let duplicateCount = 0
    const itemsToInsert = []

    for (const v of validItems) {
      const { rows: existingRows } = await pool.query(
        `SELECT id FROM transactions
         WHERE instance_id = $1
           AND date = COALESCE($4::date, CURRENT_DATE)
           AND LOWER(TRIM(name)) = LOWER(TRIM($2))
           AND ABS(amount - $3) < 0.01
           AND type = 'expense'
         LIMIT 1`,
        [instanceId, v.itemName, v.amount, receiptDate]
      )

      if (existingRows.length > 0) {
        duplicateCount++
      } else {
        itemsToInsert.push(v)
      }
    }

    if (itemsToInsert.length === 0) {
      return sendTelegramMessage(chatId, '⚠️ *Этот чек уже был добавлен ранее!*\n\nВсе позиции из этого чека уже зарегистрированы в вашем бюджете.')
    }

    // Insert transactions into instance
    let totalAdded = 0
    const itemSummaries = []

    for (const v of itemsToInsert) {
      const resolvedCat = await resolveCategoryByName(instanceId, v.catName, 'expense')
      const txId = 'rcpt-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6)
      const comment = v.qty !== 1 ? `Чек из бота (${v.qty}x ${v.price}₽)` : 'Чек из бота'

      await pool.query(
        `INSERT INTO transactions (id, name, date, type, amount, price, quantity, category_id, comment, instance_id)
         VALUES ($1, $2, COALESCE($3::date, CURRENT_DATE), 'expense', $4, $5, $6, $7, $8, $9)`,
        [txId, v.itemName, receiptDate, v.amount, v.price, v.qty, resolvedCat.id, comment, instanceId]
      )

      totalAdded += v.amount
      itemSummaries.push(`• ${v.itemName}: *${v.amount.toFixed(0)} ₽* (${resolvedCat.name})`)
    }

    const webAppUrl = await getAuthUrlForTgUser(tgId, instanceId)
    let reply = `✅ *Чек успешно обработан!*\n\n` +
      `Добавлено расходов на сумму: *${totalAdded.toFixed(0)} ₽*\n\n` +
      itemSummaries.join('\n')

    if (duplicateCount > 0) {
      reply += `\n\nℹ️ _Пропущено уже добавленных ранее позиций: ${duplicateCount}_`
    }

    reply += `\n\n📊 Откройте [TIIN Finance](${webAppUrl}), чтобы увидеть аналитику!`

    return sendTelegramMessage(chatId, reply, {
      reply_markup: {
        inline_keyboard: [
          [{ text: '📊 Посмотреть в приложении', web_app: { url: webAppUrl } }]
        ]
      }
    })
  }

  // 3. Handle Text Expense Input (e.g., "Кофе 250", "Такси 450 вокзал")
  if (msg.text) {
    const text = msg.text.trim()
    const match = text.match(/^(.+?)\s+(\d+(?:[\.,]\d+)?)(?:\s+(.*))?$/)

    if (match) {
      const name = match[1].trim()
      const amount = parseFloat(match[2].replace(',', '.'))
      const comment = match[3] || ''

      if (amount > 0) {
        // Check for duplicate text expense today
        const { rows: existingTextRows } = await pool.query(
          `SELECT id FROM transactions
           WHERE instance_id = $1
             AND date = CURRENT_DATE
             AND LOWER(TRIM(name)) = LOWER(TRIM($2))
             AND ABS(amount - $3) < 0.01
             AND type = 'expense'
           LIMIT 1`,
          [instanceId, name, amount]
        )

        if (existingTextRows.length > 0) {
          return sendTelegramMessage(chatId, `⚠️ *Такой расход уже добавлен сегодня!*\n\n📌 *${name}*: ${amount} ₽ уже есть в базе за сегодня.`)
        }

        const existingCats = await getInstanceCategories(instanceId, 'expense')
        const categoryName = predictCategory(name, existingCats)
        const resolvedCat = await resolveCategoryByName(instanceId, categoryName, 'expense')
        const txId = 'bot-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6)

        await pool.query(
          `INSERT INTO transactions (id, name, date, type, amount, category_id, comment, instance_id)
           VALUES ($1, $2, CURRENT_DATE, 'expense', $3, $4, $5, $6)`,
          [txId, name, amount, resolvedCat.id, comment || 'Добавлено через бота', instanceId]
        )

        const webAppUrl = await getAuthUrlForTgUser(tgId, instanceId)
        return sendTelegramMessage(chatId, `✅ *Расход добавлен!*\n\n📌 *${name}*: ${amount} ₽\n📂 Категория: *${resolvedCat.name}*`, {
          reply_markup: {
            inline_keyboard: [
              [{ text: '📊 Посмотреть в приложении', web_app: { url: webAppUrl } }]
            ]
          }
        })
      }
    }
  }
}

// Gemini Vision 2.5 Flash receipt OCR parsing with dynamic instance categories
async function parseReceiptImageWithGemini(base64Image, mimeType, availableCategories = []) {
  if (!GEMINI_API_KEY) return null

  const catList = availableCategories.length > 0 
    ? availableCategories.map(c => `"${c.name}"`).join(', ')
    : '"продукты", "автомобиль", "готовая еда", "ЖКУ", "здоровье", "одежда", "развлечения", "связь", "подарки", "питомцы", "прочие нужды"'

  const prompt = `Ты умный парсер кассовых чеков. Извлеки дату покупки и все купленные товары/услуги из фотографии чека и распредели по существующим категориям бюджета.
Верни ТОЛЬКО валидный JSON объект без дополнительного текста.
Формат:
{
  "date": "2026-08-09",
  "items": [
    { "name": "Куриная голень", "price": 299.90, "quantity": 2.194, "amount": 657.98, "category": "продукты" }
  ]
}
Правила:
- date: дата совершения покупки (на чеке может быть в формате DD.MM.YYYY, например "09.08.2026", или YYYY-MM-DD "2026-08-09"). Верни дату строго в формате YYYY-MM-DD ("2026-08-09") или исходную строку даты. Если даты нет/не видно, верни null.
- items: массив позиций товаров/услуг:
  * name: Очисти от артикулов и кодов, напиши короткое аккуратное наименование на русском (например: "АИ-95", "Хлеб белый", "Кофе капучино", "Куриная голень")
  * price: цена за 1 единицу/кг/штуку (например: 299.90).
  * quantity: количество или вес (например: 1, 2, 2.194, 0.500).
  * amount: итоговая стоимость строки/позиции в чеке (price * quantity, например: 657.98).
  * category: ОБЯЗАТЕЛЬНО выбери наиболее подходящую категорию ТОЛЬКО из списка существующих категорий пользователя: [${catList}].
    - Бензин, АЗС, заправка, омыватель, мойка -> "автомобиль" (или аналогичная автомобильная категория из списка).
    - Кофе, бургеры, рестораны, доставка еды -> "готовая еда" (или "продукты", если нет готовой еды).
    - Аптеки, лекарства, врачи -> "здоровье".
    - Если ничего не подходит, выбери "прочие нужды" или "без классификации".
- Игнорируй общие строки ИТОГО, НДС, ИНН, сдача, скидки по чеку.`

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [
              { text: prompt },
              { inline_data: { mime_type: mimeType, data: base64Image } }
            ]
          }]
        })
      }
    )
    const data = await res.json()
    const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}'
    
    // Check if JSON object or array was returned
    const objMatch = content.match(/\{[\s\S]*\}/)
    if (objMatch) {
      const parsed = JSON.parse(objMatch[0])
      if (Array.isArray(parsed.items)) {
        return parsed
      }
    }
    const arrMatch = content.match(/\[[\s\S]*\]/)
    if (arrMatch) {
      const items = JSON.parse(arrMatch[0])
      return { date: null, items }
    }
    return null
  } catch (err) {
    console.error('[Gemini Vision Error]', err)
    return null
  }
}

// Get linked user instance ID or fallback to instance ID 1 (default)
async function getUserInstanceId(tgId) {
  try {
    const { rows } = await pool.query(
      'SELECT instance_id FROM telegram_finance_instances WHERE tg_id = $1',
      [tgId]
    )
    if (rows.length) return rows[0].instance_id
  } catch (err) {}
  return 1 // Fallback default instance
}

// Helper to fetch all categories for instance
async function getInstanceCategories(instanceId, type = 'expense') {
  try {
    const { rows } = await pool.query(
      `SELECT id, name FROM categories 
       WHERE (instance_id = $1 OR (instance_id IS NULL AND is_default = TRUE))
         AND type = $2
       ORDER BY (instance_id = $1) DESC, id ASC`,
      [instanceId, type]
    )
    return rows
  } catch (err) {
    return []
  }
}

// Helper to resolve category by name without creating duplicate/unwanted categories
async function resolveCategoryByName(instanceId, name, type = 'expense') {
  try {
    const cats = await getInstanceCategories(instanceId, type)
    if (!cats.length) return { id: 1, name: 'продукты' }

    const clean = (name || '').trim().toLowerCase()

    // 1. Exact case-insensitive match
    const exact = cats.find(c => c.name.trim().toLowerCase() === clean)
    if (exact) return exact

    // 2. Synonyms map for standard Russian financial terms
    const synonymMap = {
      'транспорт': ['автомобиль', 'проезд в автобусах', 'такси'],
      'авто': ['автомобиль'],
      'бензин': ['автомобиль'],
      'топливо': ['автомобиль'],
      'азс': ['автомобиль'],
      'кафе': ['готовая еда', 'продукты'],
      'ресторан': ['готовая еда', 'продукты'],
      'фастфуд': ['готовая еда', 'продукты'],
      'еда': ['продукты', 'готовая еда'],
      'супермаркет': ['продукты'],
      'аптека': ['здоровье'],
      'лекарства': ['здоровье'],
      'медицина': ['здоровье'],
      'жкх': ['жку', 'ЖКУ'],
      'коммуналка': ['жку', 'ЖКУ'],
      'связь': ['связь'],
      'интернет': ['связь'],
      'телефон': ['связь'],
      'сладости': ['сладости', 'продукты'],
      'десерт': ['сладости', 'продукты']
    }

    if (synonymMap[clean]) {
      for (const targetName of synonymMap[clean]) {
        const found = cats.find(c => c.name.trim().toLowerCase() === targetName.toLowerCase())
        if (found) return found
      }
    }

    // 3. Substring match (e.g. "авто" matches "автомобиль")
    const sub = cats.find(c => {
      const cn = c.name.trim().toLowerCase()
      return clean.includes(cn) || cn.includes(clean)
    })
    if (sub) return sub

    // 4. Default fallback: "без классификации" -> "прочие нужды" -> first available
    const fallback = cats.find(c => c.name.toLowerCase().includes('без классификации'))
      || cats.find(c => c.name.toLowerCase().includes('проч'))
      || cats[0]

    return fallback
  } catch (err) {
    return { id: 1, name: 'продукты' }
  }
}

// Rule-based category predictor for quick text expenses
function predictCategory(name, availableCategories = []) {
  const n = (name || '').toLowerCase()
  const catNames = availableCategories.map(c => c.name.trim().toLowerCase())

  if (n.includes('бензин') || n.includes('аи-') || n.includes('азс') || n.includes('лукойл') || n.includes('газпром') || n.includes('саханефтегазсбыт') || n.includes('сибойл') || n.includes('мойк') || n.includes('шиномонтаж') || n.includes('масло') || n.includes('авто')) {
    if (catNames.includes('автомобиль')) return 'автомобиль'
    if (catNames.includes('транспорт')) return 'транспорт'
  }
  if (n.includes('кофе') || n.includes('кафе') || n.includes('ресторан') || n.includes('обед') || n.includes('пицца') || n.includes('бургер') || n.includes('шаурма') || n.includes('додо') || n.includes('суши')) {
    if (catNames.includes('готовая еда')) return 'готовая еда'
    if (catNames.includes('кафе и рестораны')) return 'кафе и рестораны'
  }
  if (n.includes('автобус') || n.includes('метро') || n.includes('маршрутк') || n.includes('проезд')) {
    if (catNames.includes('проезд в автобусах')) return 'проезд в автобусах'
  }
  if (n.includes('такси') || n.includes('яндекс го') || n.includes('драйв') || n.includes('indrive')) {
    if (catNames.includes('такси')) return 'такси'
    if (catNames.includes('автомобиль')) return 'автомобиль'
  }
  if (n.includes('аптека') || n.includes('врач') || n.includes('лекарств') || n.includes('клиник') || n.includes('анализ') || n.includes('стоматолог')) {
    if (catNames.includes('здоровье')) return 'здоровье'
  }
  if (n.includes('кино') || n.includes('игра') || n.includes('подписка') || n.includes('театр') || n.includes('парк')) {
    if (catNames.includes('развлечения')) return 'развлечения'
  }
  if (n.includes('торт') || n.includes('шоколад') || n.includes('конфет') || n.includes('морожен') || n.includes('выпечка')) {
    if (catNames.includes('сладости')) return 'сладости'
  }
  if (n.includes('жкх') || n.includes('квартплат') || n.includes('электричеств') || n.includes('свет') || n.includes('газ') || n.includes('водоканал')) {
    if (catNames.includes('жку')) return 'ЖКУ'
  }

  if (catNames.includes('продукты')) return 'продукты'
  return availableCategories[0]?.name || 'продукты'
}
