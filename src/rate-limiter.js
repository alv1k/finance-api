// In-memory rate limiting module for security protection

const attemptsMap = new Map()

// Cleanup stale memory records every 10 minutes
setInterval(() => {
  const now = Date.now()
  for (const [key, data] of attemptsMap.entries()) {
    if (now > data.resetTime) {
      attemptsMap.delete(key)
    }
  }
}, 10 * 60 * 1000)

export function createRateLimiter(options = {}) {
  const windowMs = options.windowMs || 15 * 60 * 1000 // 15 min default
  const maxAttempts = options.maxAttempts || 5
  const message = options.message || 'Слишком много попыток. Пожалуйста, попробуйте позже.'

  return function rateLimiterMiddleware(req, res, next) {
    // Get real client IP considering Nginx proxy headers
    const clientIp = req.headers['x-real-ip'] || 
                     req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.ip || 
                     'unknown'

    const prefix = options.prefix || 'global'
    const key = `${prefix}:${clientIp}`
    const now = Date.now()

    let record = attemptsMap.get(key)

    if (!record || now > record.resetTime) {
      record = {
        count: 1,
        resetTime: now + windowMs
      }
      attemptsMap.set(key, record)
      return next()
    }

    if (record.count >= maxAttempts) {
      const retryAfterSec = Math.ceil((record.resetTime - now) / 1000)
      res.setHeader('Retry-After', retryAfterSec)
      return res.status(429).json({
        error: message,
        retry_after_seconds: retryAfterSec
      })
    }

    record.count++
    attemptsMap.set(key, record)
    next()
  }
}

// Reset attempts for an IP on successful login
export function clearRateLimit(prefix, req) {
  const clientIp = req.headers['x-real-ip'] || 
                   req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                   req.ip || 
                   'unknown'
  const key = `${prefix}:${clientIp}`
  attemptsMap.delete(key)
}

// Input sanitizer for username
export function sanitizeUsername(username) {
  if (typeof username !== 'string') return ''
  // Trim, remove control characters and dangerous spaces
  let sanitized = username.trim().replace(/[\r\n\t\0]/g, '')
  return sanitized
}
