/**
 * Authentication Middleware for OpenClaw Command Center
 * Supports API Key authentication via header or query parameter
 */

import crypto from 'node:crypto';

// Load API keys from environment (comma-separated)
const API_KEYS = (process.env.API_KEYS || '')
  .split(',')
  .map(k => k.trim())
  .filter(k => k.length > 0);

// Session store for WebSocket connections
const sessions = new Map();

// Rate limiting store
const rateLimitStore = new Map();

/**
 * Generate a secure session token
 */
export function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Validate API key
 */
export function isValidApiKey(apiKey) {
  if (!API_KEYS.length) {
    console.warn('[auth] WARNING: No API keys configured! Set API_KEYS environment variable.');
    return false; // Fail closed when no keys configured
  }
  return API_KEYS.includes(apiKey);
}

/**
 * Create a session for WebSocket
 */
export function createSession(apiKey) {
  const token = generateSessionToken();
  const session = {
    token,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    apiKey: crypto.createHash('sha256').update(apiKey).digest('hex').slice(0, 8),
  };
  sessions.set(token, session);
  return token;
}

/**
 * Validate WebSocket session
 */
export function validateSession(token) {
  const session = sessions.get(token);
  if (!session) return false;
  
  // Session expires after 24 hours
  const maxAge = 24 * 60 * 60 * 1000;
  if (Date.now() - session.createdAt > maxAge) {
    sessions.delete(token);
    return false;
  }
  
  // Update last activity
  session.lastActivity = Date.now();
  return true;
}

/**
 * Clean up expired sessions
 */
export function cleanupSessions() {
  const maxAge = 24 * 60 * 60 * 1000;
  const now = Date.now();
  let cleaned = 0;
  
  for (const [token, session] of sessions) {
    if (now - session.lastActivity > maxAge) {
      sessions.delete(token);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    console.log(`[auth] Cleaned up ${cleaned} expired sessions`);
  }
}

/**
 * Rate limiting middleware
 */
export function rateLimit(options = {}) {
  const {
    windowMs = 60 * 1000, // 1 minute window
    maxRequests = 60, // max requests per window
    keyGenerator = (req) => req.ip || req.connection.remoteAddress,
  } = options;

  return (req, res, next) => {
    const key = keyGenerator(req);
    const now = Date.now();
    
    let record = rateLimitStore.get(key);
    
    if (!record || now - record.windowStart > windowMs) {
      record = { windowStart: now, count: 0 };
    }
    
    record.count++;
    rateLimitStore.set(key, record);
    
    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - record.count));
    res.setHeader('X-RateLimit-Reset', new Date(record.windowStart + windowMs).toISOString());
    
    if (record.count > maxRequests) {
      return res.status(429).json({
        error: 'Too many requests',
        retryAfter: Math.ceil((record.windowStart + windowMs - now) / 1000),
      });
    }
    
    next();
  };
}

/**
 * API Key authentication middleware for HTTP routes
 */
export function requireAuth(req, res, next) {
  // Check header first
  let credential = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');

  // Fallback to query parameter (less secure, use with caution)
  if (!credential) {
    credential = req.query.apiKey;
  }

  if (!credential) {
    return res.status(401).json({ error: 'API key required' });
  }

  // Accept either a valid API key or a valid session token
  if (!isValidApiKey(credential) && !validateSession(credential)) {
    logSecurityEvent('invalid_api_key', { ip: req.ip, path: req.path });
    return res.status(403).json({ error: 'Invalid API key' });
  }

  req.authenticated = true;
  req.apiKey = credential;
  next();
}

/**
 * Optional auth - allows but tracks unauthenticated access
 */
export function optionalAuth(req, res, next) {
  let apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (apiKey && isValidApiKey(apiKey)) {
    req.authenticated = true;
    req.apiKey = apiKey;
  } else {
    req.authenticated = false;
  }
  
  next();
}

/**
 * Security event logging
 */
const securityLog = [];

export function logSecurityEvent(type, details = {}) {
  const event = {
    type,
    timestamp: new Date().toISOString(),
    ...details,
  };
  
  securityLog.push(event);
  
  // Keep only last 1000 events
  if (securityLog.length > 1000) {
    securityLog.shift();
  }
  
  console.warn(`[security] ${type}:`, JSON.stringify(details));
}

export function getSecurityLog(limit = 100) {
  return securityLog.slice(-limit);
}

// Cleanup interval for sessions and rate limits
setInterval(() => {
  cleanupSessions();
  
  // Clean up old rate limit records
  const now = Date.now();
  for (const [key, record] of rateLimitStore) {
    if (now - record.windowStart > 120000) { // 2 minutes
      rateLimitStore.delete(key);
    }
  }
}, 60000); // Every minute

export default {
  requireAuth,
  optionalAuth,
  rateLimit,
  isValidApiKey,
  createSession,
  validateSession,
  logSecurityEvent,
  getSecurityLog,
};
