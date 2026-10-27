import crypto from 'crypto'

const AGY_INFERENCE_URL = process.env.AGY_INFERENCE_URL || 'http://agy-inference:8799'
const AGY_INTERNAL_KEY = process.env.AGY_INTERNAL_KEY || '4a25446d88fc2c320ddd53575626866839888140f64b550e'

// Dictionary of keyword rules for fast offline zero-latency matching
const CATEGORY_RULES = [
  {
    category: 'Кафе и рестораны',
    keywords: [
      'обед', 'ужин', 'завтрак', 'ланч', 'кофе', 'капучино', 'латте', 'американо', 'раф',
      'пицца', 'бургер', 'шаурма', 'шаверма', 'додо', 'кфс', 'kfc', 'ростикс', 'вкусно и точка', 'макдак',
      'ресторан', 'бар', 'паб', 'столовая', 'кафе', 'суши', 'роллы', 'фастфуд', 'доставка',
      'яндекс еда', 'яндекс лавка', 'самокат', 'купер', 'деливери'
    ]
  },
  {
    category: 'Продукты',
    keywords: [
      'продукты', 'супермаркет', 'магазин', 'пятерочка', 'пятерка', 'перекресток', 'магнит',
      'ашан', 'лента', 'спар', 'spar', 'дикси', 'вкусвилл', 'метро', 'молоко', 'хлеб', 'мясо',
      'сыр', 'масло', 'фрукты', 'овощи', 'яйца', 'творог', 'колбаса', 'курица', 'рыба', 'еда'
    ]
  },
  {
    category: 'Транспорт',
    keywords: [
      'такси', 'яндекс го', 'яндекс такси', 'убер', 'uber', 'метро', 'автобус', 'проезд',
      'маршрутка', 'билет', 'бензин', 'заправка', 'азс', 'лукойл', 'газпром', 'роснефть',
      'парковка', 'мойка', 'автомойка', 'шиномонтаж', 'каршеринг', 'ситидрайв', 'дерен', 'солярка', 'дизель'
    ]
  },
  {
    category: 'Здоровье и аптека',
    keywords: [
      'аптека', 'лекарства', 'таблетки', 'витамины', 'врач', 'клиника', 'стоматолог', 'зуб',
      'анализы', 'больница', 'медицина', 'капли', 'мазь'
    ]
  },
  {
    category: 'Жилье и ЖКХ',
    keywords: [
      'аренда', 'квартира', 'жкх', 'квартплата', 'свет', 'электричество', 'газ', 'отопление',
      'вода', 'домофон', 'управляющая компания', 'ук'
    ]
  },
  {
    category: 'Связь и интернет',
    keywords: [
      'интернет', 'связь', 'мтс', 'мегафон', 'билайн', 'т2', 'теле2', 'ростелеком', 'домру', 'баланс', 'симка'
    ]
  },
  {
    category: 'Развлечения и подписки',
    keywords: [
      'кино', 'кинотеатр', 'фильм', 'театр', 'концерт', 'игра', 'steam', 'стим', 'плейстейшн',
      'подписка', 'кинопоиск', 'яндекс плюс', 'ютуб', 'youtube', 'спотифай', 'spotify', 'боулинг', 'клуб'
    ]
  },
  {
    category: 'Одежда и покупки',
    keywords: [
      'одежда', 'обувь', 'куртка', 'кроссовки', 'ботинки', 'штаны', 'джинсы', 'футболка',
      'wildberries', 'вайлдберриз', 'вайлдбериз', 'вб', 'wb', 'ozon', 'озон', 'алиэкспресс', 'aliexpress', 'zara'
    ]
  },
  {
    category: 'Доход',
    keywords: [
      'зарплата', 'зп', 'аванс', 'получка', 'премия', 'доход', 'вернули', 'возврат', 'долг',
      'кэшбэк', 'кешбэк', 'дивиденды', 'проценты', 'перевод от', 'приход'
    ]
  },
  {
    category: 'Подарки',
    keywords: [
      'подарок', 'цветы', 'букет', 'др', 'день рождения', 'праздник'
    ]
  }
]

const INCOME_KEYWORDS = [
  'зарплата', 'зп', 'аванс', 'получка', 'премия', 'доход', 'вернули', 'возврат', 'кэшбэк', 'кешбэк', 'дивиденды', 'приход'
]

/**
 * Normalizes date from Russian natural phrases
 */
function extractDate(text) {
  const lower = text.toLowerCase()
  const today = new Date()
  
  if (lower.includes('позавчера')) {
    const d = new Date(today.getTime() - 2 * 24 * 60 * 60 * 1000)
    return { date: d.toISOString().split('T')[0], cleanedText: text.replace(/позавчера/gi, '') }
  }
  if (lower.includes('вчера')) {
    const d = new Date(today.getTime() - 24 * 60 * 60 * 1000)
    return { date: d.toISOString().split('T')[0], cleanedText: text.replace(/вчера/gi, '') }
  }
  if (lower.includes('сегодня')) {
    return { date: today.toISOString().split('T')[0], cleanedText: text.replace(/сегодня/gi, '') }
  }

  return { date: today.toISOString().split('T')[0], cleanedText: text }
}

/**
 * Parses numeric amount from text (e.g. 350, 1.5к, 2000р, $50)
 */
function extractAmount(text) {
  // 1. Check "1.5к" / "2k" pattern
  const kMatch = text.match(/(?:^|\s)(\d+(?:[\.,]\d+)?)\s*(?:к|k|тыс|тысяч)(?:\s|$)/i)
  if (kMatch) {
    const num = parseFloat(kMatch[1].replace(',', '.')) * 1000
    const rawMatch = kMatch[0]
    return { amount: Math.round(num * 100) / 100, rawMatch }
  }

  // 2. Check standard numbers: 350, 350.50, 350р, 350 руб, 350rub, 350 рублей, 350₽
  const numMatch = text.match(/(?:^|\s)(\d+(?:[\.,]\d+)?)\s*(?:рублей|рубля|рубль|руб|rub|р|₽|\$|€)?(?:\s|$)/i)
  if (numMatch) {
    const num = parseFloat(numMatch[1].replace(',', '.'))
    return { amount: Math.round(num * 100) / 100, rawMatch: numMatch[0] }
  }

  return null
}

/**
 * Predicts the most suitable category name based on words and existing instance categories
 */
function matchCategory(text, existingCategories = [], type = 'expense') {
  const lower = text.toLowerCase()

  // Match against user's custom categories first
  if (Array.isArray(existingCategories) && existingCategories.length > 0) {
    for (const cat of existingCategories) {
      if (cat.type === type && lower.includes(cat.name.toLowerCase())) {
        return cat.name
      }
    }
  }

  // Match against built-in dictionary with Cyrillic-safe boundary
  for (const rule of CATEGORY_RULES) {
    for (const kw of rule.keywords) {
      const regex = new RegExp(`(^|[^a-zа-яё0-9])${kw}([^a-zа-яё0-9]|$)`, 'iu')
      if (regex.test(lower)) {
        // Check if user has an existing category that matches rule name
        if (Array.isArray(existingCategories)) {
          const matched = existingCategories.find(
            c => c.name.toLowerCase() === rule.category.toLowerCase() ||
                 rule.category.toLowerCase().includes(c.name.toLowerCase()) ||
                 c.name.toLowerCase().includes(rule.category.toLowerCase())
          )
          if (matched) return matched.name
        }
        return rule.category
      }
    }
  }

  return type === 'income' ? 'Доход' : 'Прочее'
}

/**
 * Fast Rule-Based Parser (0ms latency)
 */
export function parseFastExpense(rawText, existingCategories = []) {
  if (!rawText || typeof rawText !== 'string') return null

  let text = rawText.trim()
  if (!text) return null

  // 1. Extract Date
  const { date, cleanedText } = extractDate(text)
  text = cleanedText.trim()

  // 2. Detect Income vs Expense
  const lower = text.toLowerCase()
  let type = 'expense'
  for (const incWord of INCOME_KEYWORDS) {
    if (lower.includes(incWord)) {
      type = 'income'
      break
    }
  }

  // 3. Extract Amount
  const amtRes = extractAmount(text)
  if (!amtRes || !amtRes.amount || amtRes.amount <= 0) {
    return null // Could not find amount via regex
  }

  const amount = amtRes.amount

  // 4. Extract Name / Description
  let name = text.replace(amtRes.rawMatch, ' ').trim()
  
  // Clean assistant triggers and filler words with Unicode boundaries
  const fillerRegex = /(?:^|[^a-zа-яё0-9])(окей|гугл|google|siri|сири|алиса|привет|потратил|потрачено|купил|купила|оплатил|оплатила|взял|закинул|скинул|на|в|за|с|по|рублей|рубля|рубль|руб|р|₽)(?:[^a-zа-яё0-9]|$)/giu
  name = name.replace(fillerRegex, ' ').replace(fillerRegex, ' ')
  name = name.replace(/[,\.:;!?"'\(\)]/g, ' ').replace(/\s+/g, ' ').trim()

  if (!name) {
    name = type === 'income' ? 'Поступление' : 'Расход'
  } else {
    // Capitalize first letter
    name = name.charAt(0).toUpperCase() + name.slice(1)
  }

  // 5. Predict Category
  const category = matchCategory(rawText, existingCategories, type)

  return [
    {
      name,
      amount,
      type,
      category,
      date,
      comment: 'Быстрый ввод'
    }
  ]
}

/**
 * Smart Fallback Parser via Local AGY Inference Gateway
 */
export async function parseWithAgyInference(rawText, existingCategories = []) {
  try {
    const catListStr = (existingCategories || []).map(c => c.name).join(', ')
    const todayStr = new Date().toISOString().split('T')[0]

    const prompt = `Ты финансовый ассистент. Извлеки список финансовых операций из текста на русском языке.
Сегодняшняя дата: ${todayStr}
Существующие категории пользователя: [${catListStr || 'Кафе и рестораны, Продукты, Транспорт, Жилье, Связь, Здоровье, Одежда, Развлечения, Доход, Прочее'}]

Верни ТОЛЬКО валидный JSON массив объектов с такой структурой (без markdown и пояснений):
[
  {
    "name": "Название покупки или дохода с заглавной буквы",
    "amount": 350.0,
    "type": "expense" или "income",
    "category": "Название наиболее подходящей категории",
    "date": "YYYY-MM-DD"
  }
]

Текст пользователя: "${rawText}"`

    const response = await fetch(`${AGY_INFERENCE_URL}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': AGY_INTERNAL_KEY,
        'X-Service-ID': 'finance-api'
      },
      body: JSON.stringify({
        messages: [
          { role: 'user', content: prompt }
        ],
        temperature: 0.1
      }),
      signal: AbortSignal.timeout(6000)
    })

    if (!response.ok) {
      console.error('[AGY Quick NLP Error] HTTP', response.status)
      return null
    }

    const data = await response.json()
    const content = data.choices?.[0]?.message?.content || ''
    const cleanJson = content.replace(/```json/g, '').replace(/```/g, '').trim()
    const parsed = JSON.parse(cleanJson)

    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed.map(item => ({
        name: item.name || 'Расход',
        amount: parseFloat(item.amount) || 0,
        type: item.type === 'income' ? 'income' : 'expense',
        category: item.category || (item.type === 'income' ? 'Доход' : 'Прочее'),
        date: item.date || todayStr,
        comment: 'Smart AI ввод'
      })).filter(item => item.amount > 0)
    }
  } catch (err) {
    console.error('[AGY Quick NLP Exception]', err.message)
  }
  return null
}

/**
 * Main Quick Expense Resolver
 */
export async function parseQuickExpense(text, existingCategories = []) {
  if (!text || typeof text !== 'string') return []

  // Step 1: Try zero-latency fast regex parser
  const fastResult = parseFastExpense(text, existingCategories)
  if (fastResult && fastResult.length > 0) {
    return fastResult
  }

  // Step 2: Fallback to AGY Inference Gateway for complex phrases
  const smartResult = await parseWithAgyInference(text, existingCategories)
  if (smartResult && smartResult.length > 0) {
    return smartResult
  }

  return []
}
