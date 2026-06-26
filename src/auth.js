import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import pool from './db.js'

const JWT_SECRET = process.env.JWT_SECRET || 'change_me_in_production'
const SALT_ROUNDS = 12

export async function hashPassword(password) {
  return bcrypt.hash(password, SALT_ROUNDS)
}

export async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash)
}

export function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' })
}

export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET)
}

export function authMiddleware(req, res, next) {
  const auth = req.headers.authorization
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' })
  }
  try {
    const payload = verifyToken(auth.slice(7))
    req.user = payload
    next()
  } catch {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

export function optionalAuthMiddleware(req, res, next) {
  const auth = req.headers.authorization
  if (auth && auth.startsWith('Bearer ')) {
    try {
      req.user = verifyToken(auth.slice(7))
    } catch {}
  }
  next()
}

export function adminMiddleware(req, res, next) {
  if (!req.user?.is_admin) {
    return res.status(403).json({ error: 'Admin access required' })
  }
  next()
}

export async function instanceMiddleware(req, res, next) {
  const instanceId = req.params.instanceId || req.query.instance_id || req.body.instance_id
  if (!instanceId) {
    return res.status(400).json({ error: 'instance_id required' })
  }
  const { rows } = await pool.query(
    'SELECT role FROM instance_members WHERE instance_id = $1 AND user_id = $2',
    [instanceId, req.user.id]
  )
  if (!rows.length) {
    return res.status(403).json({ error: 'Not a member of this instance' })
  }
  req.instanceId = parseInt(instanceId)
  req.memberRole = rows[0].role
  next()
}

export async function instanceOwnerMiddleware(req, res, next) {
  if (req.memberRole !== 'owner') {
    return res.status(403).json({ error: 'Owner access required' })
  }
  next()
}
