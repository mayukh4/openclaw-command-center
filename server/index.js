/**
 * OpenClaw Command Center - SECURE VERSION
 * 
 * Security improvements:
 * - API Key authentication
 * - Rate limiting
 * - Helmet security headers
 * - Input validation
 * - WebSocket authentication
 * - Security logging
 * - CORS protection
 */

import express from 'express';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync, existsSync } from 'node:fs';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { execFile } from 'node:child_process';
import os from 'node:os';
import multer from 'multer';
import crypto from 'node:crypto';
import helmet from 'helmet';
import cors from 'cors';
import config from './config.js';
import OpenClawBridge from './openclaw-bridge.js';
import { transcribe, speak } from './voice.js';
import {
  requireAuth,
  optionalAuth,
  rateLimit,
  isValidApiKey,
  createSession,
  validateSession,
  logSecurityEvent,
  getSecurityLog,
} from './auth.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();

// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Trust proxy - set to true if behind reverse proxy
app.set('trust proxy', process.env.TRUST_PROXY === 'true');

// Helmet security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "https:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : ['http://localhost:3000'],
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400,
};
app.use(cors(corsOptions));

// Body parsing with limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Request ID for tracking
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[request] ${req.method} ${req.path} ${res.statusCode} ${duration}ms (${req.id})`);
  });
  next();
});

// ============================================
// HTTPS/HTTP SERVER SETUP
// ============================================

const certPath = join(__dirname, 'cert.pem');
const keyPath = join(__dirname, 'key.pem');
const useHttps = existsSync(certPath) && existsSync(keyPath);

let server;
if (useHttps) {
  server = createHttpsServer({
    cert: readFileSync(certPath),
    key: readFileSync(keyPath),
    secureOptions: crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
  }, app);
  console.log('[server] TLS enabled with secure options');
} else {
  server = createHttpServer(app);
  console.log('[server] WARNING: Running without TLS. Use reverse proxy with SSL for production!');
}

// ============================================
// FILE UPLOAD CONFIGURATION
// ============================================

// Allowed MIME types for audio uploads
const ALLOWED_AUDIO_TYPES = [
  'audio/webm',
  'audio/wav',
  'audio/mpeg',
  'audio/mp3',
  'audio/ogg',
  'audio/mp4',
  'audio/x-m4a',
];

// File filter for uploads
const audioFileFilter = (req, file, cb) => {
  if (ALLOWED_AUDIO_TYPES.includes(file.mimetype)) {
    cb(null, true);
  } else {
    logSecurityEvent('invalid_file_type', {
      ip: req.ip,
      mimetype: file.mimetype,
      originalname: file.originalname,
    });
    cb(new Error(`Invalid file type: ${file.mimetype}. Allowed: ${ALLOWED_AUDIO_TYPES.join(', ')}`), false);
  }
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
    files: 1,
  },
  fileFilter: audioFileFilter,
});

// ============================================
// INPUT VALIDATION
// ============================================

// Valid agent names (whitelist)
const VALID_AGENTS = ['main', 'researcher', 'coder', 'engineer', 'assistant'];

function validateAgentName(agent) {
  if (!agent || typeof agent !== 'string') return 'main';
  const sanitized = agent.toLowerCase().trim().replace(/[^a-z0-9_-]/g, '');
  return VALID_AGENTS.includes(sanitized) ? sanitized : 'main';
}

function validateMessage(message) {
  if (!message || typeof message !== 'string') {
    throw new Error('Message is required and must be a string');
  }
  if (message.length > 10000) {
    throw new Error('Message exceeds maximum length of 10000 characters');
  }
  // Remove potential command injection characters
  return message.replace(/[\x00-\x1f\x7f]/g, '').trim();
}

// ============================================
// STATIC FILES (Public - no auth required)
// ============================================

app.use(express.static(join(__dirname, '..', 'public'), {
  maxAge: '1h',
  etag: true,
  lastModified: true,
}));

// ============================================
// PUBLIC ENDPOINTS (with rate limiting)
// ============================================

// Health endpoint - basic info (rate limited)
app.get('/api/health', rateLimit({ windowMs: 60000, maxRequests: 120 }), (req, res) => {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const memPct = Math.round(((totalMem - freeMem) / totalMem) * 100);
  const loadAvg = os.loadavg()[0];
  const cpuPct = Math.min(100, Math.round((loadAvg / cpus.length) * 100));

  execFile('sh', ['-c', "df / --output=pcent | tail -1 | tr -d ' %'; echo; cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0"],
    { timeout: 5000 },
    (err, stdout) => {
      const lines = (stdout || '').trim().split('\n');
      const diskPct = parseInt(lines[0]) || 0;
      const tempC = Math.round((parseInt(lines[1]) || 0) / 1000);
      res.json({
        cpu_pct: cpuPct,
        mem_pct: memPct,
        disk_pct: diskPct,
        temp_c: tempC,
        uptime: Math.floor(os.uptime()),
      });
    }
  );
});

// UI config - agent display names, colors, voices
app.get('/api/ui-config', rateLimit({ windowMs: 60000, maxRequests: 120 }), (req, res) => {
  const defaults = {
    agents: {
      'main':   { name: 'Jansky', color: '#FFD700', hairColor: '#FFD700', clothColor: '#998100', voice: 'onyx'  },
      'claw-1': { name: 'Orbit',  color: '#00DDFF', hairColor: '#00DDFF', clothColor: '#008499', voice: 'echo'  },
      'claw-2': { name: 'Nova',   color: '#AA66FF', hairColor: '#AA66FF', clothColor: '#663D99', voice: 'fable' },
    },
  };
  const configPath = join(__dirname, '..', 'config', 'ui.json');
  if (existsSync(configPath)) {
    try {
      const parsed = JSON.parse(readFileSync(configPath, 'utf8'));
      // Merge: only override known agent IDs and known fields
      for (const agentId of ['main', 'claw-1', 'claw-2']) {
        if (parsed.agents?.[agentId]) {
          const { name, color, hairColor, clothColor, voice } = parsed.agents[agentId];
          if (name       && typeof name       === 'string') defaults.agents[agentId].name       = name;
          if (color      && typeof color      === 'string') defaults.agents[agentId].color      = color;
          if (hairColor  && typeof hairColor  === 'string') defaults.agents[agentId].hairColor  = hairColor;
          if (clothColor && typeof clothColor === 'string') defaults.agents[agentId].clothColor = clothColor;
          if (voice      && typeof voice      === 'string') defaults.agents[agentId].voice      = voice;
        }
      }
    } catch (err) {
      console.warn('[ui-config] Failed to parse config/ui.json, using defaults:', err.message);
    }
  }
  res.json(defaults);
});

// Local browser token - no API key needed, localhost only
app.get('/api/auth/local-token', rateLimit({ windowMs: 60000, maxRequests: 30 }), (req, res) => {
  const ip = req.socket.remoteAddress;
  if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
    return res.status(403).json({ error: 'Local access only' });
  }
  const token = createSession('local-browser');
  res.json({ token });
});

// ============================================
// PROTECTED ENDPOINTS (require authentication)
// ============================================

// Authentication endpoint - exchange API key for session token
app.post('/api/auth/session', rateLimit({ windowMs: 60000, maxRequests: 10 }), (req, res) => {
  const { apiKey } = req.body;
  
  if (!apiKey) {
    return res.status(400).json({ error: 'API key required in request body' });
  }
  
  if (!isValidApiKey(apiKey)) {
    logSecurityEvent('failed_auth_attempt', { ip: req.ip });
    return res.status(403).json({ error: 'Invalid API key' });
  }
  
  const sessionToken = createSession(apiKey);
  logSecurityEvent('session_created', { ip: req.ip });
  
  res.json({
    success: true,
    sessionToken,
    expiresIn: 86400, // 24 hours
  });
});

// Status endpoint
app.get('/api/status', requireAuth, rateLimit({ windowMs: 60000, maxRequests: 120 }), (req, res) => {
  res.json({
    uptime: process.uptime(),
    bridge: bridge.getStatus(),
    clients: wss.clients.size,
    voiceEnabled: !!config.openaiApiKey,
    authenticated: true,
  });
});

// Weather endpoint (cached 10 min)
let weatherCache = { data: null, ts: 0 };
app.get('/api/weather', requireAuth, rateLimit({ windowMs: 60000, maxRequests: 60 }), async (req, res) => {
  const now = Date.now();
  if (weatherCache.data && now - weatherCache.ts < 600000) {
    return res.json(weatherCache.data);
  }
  
  try {
    // Validate and sanitize location
    const location = (config.weatherLocation || '').replace(/[^a-zA-Z0-9,\s-]/g, '').slice(0, 100);
    const resp = await fetch(`https://wttr.in/${encodeURIComponent(location)}?format=j1`);
    
    if (!resp.ok) {
      throw new Error(`Weather API returned ${resp.status}`);
    }
    
    const json = await resp.json();
    const cur = json.current_condition?.[0] || {};
    const data = {
      temp_c: parseInt(cur.temp_C) || 0,
      feels_like: parseInt(cur.FeelsLikeC) || 0,
      desc: cur.weatherDesc?.[0]?.value || 'Unknown',
      code: parseInt(cur.weatherCode) || 0,
      humidity: parseInt(cur.humidity) || 0,
      wind_kph: parseInt(cur.windspeedKmph) || 0,
      location: location.split(',')[0],
    };
    weatherCache = { data, ts: now };
    res.json(data);
  } catch (err) {
    console.error('[weather] Error:', err.message);
    res.json(weatherCache.data || { temp_c: 0, desc: 'Unavailable', code: 0 });
  }
});

// Security log endpoint (admin only - requires special header)
app.get('/api/security/log', requireAuth, rateLimit({ windowMs: 60000, maxRequests: 10 }), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  res.json({
    events: getSecurityLog(limit),
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// AGENT COMMUNICATION
// ============================================

function sendToAgent(agentId, message, requestId) {
  const target = validateAgentName(agentId);
  const sanitizedMessage = validateMessage(message);
  
  console.log(`[agent] Sending to ${target}: "${sanitizedMessage.slice(0, 80)}..." (request: ${requestId})`);

  broadcast({
    type: 'agent:thinking',
    data: { agent: target, status: 'Processing...', requestId },
  });

  const openclawBin = process.env.HOME + '/.local/bin/openclaw';
  const thinkingLevel = target === 'main' ? 'low' : 'off';
  
  execFile(
    openclawBin,
    ['agent', '--agent', target, '--thinking', thinkingLevel, '--message', sanitizedMessage],
    {
      timeout: 90000,
      env: { ...process.env, PATH: process.env.HOME + '/.local/bin:' + process.env.PATH },
      maxBuffer: 1024 * 1024, // 1MB buffer
    },
    (err, stdout, stderr) => {
      if (err) {
        console.error(`[agent] Error from ${target}:`, err.message);
        logSecurityEvent('agent_error', { agent: target, error: err.message, requestId });
        broadcast({
          type: 'agent:error',
          data: { agent: target, message: 'Agent processing failed', requestId },
        });
        return;
      }

      const response = stdout.trim().slice(0, 50000); // Limit response size
      console.log(`[agent] Response from ${target}: "${response.slice(0, 80)}..."`);

      broadcast({
        type: 'agent:responding',
        data: { agent: target, message: response, requestId },
      });
    }
  );
}

// ============================================
// VOICE ENDPOINTS (require authentication + strict rate limiting)
// ============================================

// Voice transcription
app.post(
  '/api/voice/transcribe',
  requireAuth,
  rateLimit({ windowMs: 60000, maxRequests: 20 }), // Strict limit - costs money!
  upload.single('audio'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No audio file provided' });
      }

      const targetAgent = validateAgentName(req.body?.targetAgent);
      const requestId = req.id;
      
      console.log(`[voice] Transcribing ${req.file.size} bytes for agent: ${targetAgent} (request: ${requestId})`);
      
      const text = await transcribe(req.file.buffer, req.file.originalname || 'audio.webm');
      
      // Validate transcription result
      if (typeof text !== 'string' || text.length > 5000) {
        throw new Error('Invalid transcription result');
      }
      
      console.log(`[voice] Transcribed: "${text.slice(0, 100)}"`);

      broadcast({
        type: 'voice:transcription',
        data: { text, agent: targetAgent, timestamp: Date.now(), requestId },
      });

      sendToAgent(targetAgent, text, requestId);

      res.json({ text, agent: targetAgent, requestId });
    } catch (err) {
      console.error('[voice] Transcription error:', err.message);
      logSecurityEvent('transcription_error', { error: err.message, ip: req.ip });
      res.status(500).json({ error: 'Transcription failed' });
    }
  }
);

// Voice synthesis
app.post(
  '/api/voice/speak',
  requireAuth,
  rateLimit({ windowMs: 60000, maxRequests: 30 }), // Strict limit - costs money!
  async (req, res) => {
    try {
      const { text, agent } = req.body;
      
      if (!text || typeof text !== 'string') {
        return res.status(400).json({ error: 'Text is required' });
      }
      
      if (text.length > 2000) {
        return res.status(400).json({ error: 'Text exceeds maximum length of 2000 characters' });
      }

      const validatedAgent = validateAgentName(agent);
      console.log(`[voice] Speaking as ${validatedAgent}: "${text.slice(0, 80)}..."`);
      
      const audioBuffer = await speak(text, validatedAgent);

      res.set('Content-Type', 'audio/mpeg');
      res.set('Content-Length', audioBuffer.length);
      res.set('Cache-Control', 'no-store');
      res.send(audioBuffer);
    } catch (err) {
      console.error('[voice] TTS error:', err.message);
      logSecurityEvent('tts_error', { error: err.message, ip: req.ip });
      res.status(500).json({ error: 'Speech synthesis failed' });
    }
  }
);

// ============================================
// WEBSOCKET SERVER WITH AUTHENTICATION
// ============================================

const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  let isAuthenticated = false;
  let sessionToken = null;

  console.log(`[ws] Client connected from ${clientIp} (total: ${wss.clients.size})`);

  // Send auth required message
  ws.send(JSON.stringify({
    type: 'auth:required',
    data: { message: 'Please authenticate with your session token' },
  }));

  // Authentication timeout - disconnect after 10 seconds if not authenticated
  const authTimeout = setTimeout(() => {
    if (!isAuthenticated) {
      ws.send(JSON.stringify({ type: 'auth:timeout', data: { message: 'Authentication timeout' } }));
      ws.close(1008, 'Authentication timeout');
    }
  }, 10000);

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());

      // Handle authentication
      if (msg.type === 'auth' && msg.token) {
        if (validateSession(msg.token)) {
          isAuthenticated = true;
          sessionToken = msg.token;
          clearTimeout(authTimeout);
          
          ws.send(JSON.stringify({
            type: 'auth:success',
            data: { ...bridge.getStatus(), voiceEnabled: !!config.openaiApiKey },
          }));
          
          logSecurityEvent('ws_authenticated', { ip: clientIp });
          console.log(`[ws] Client authenticated from ${clientIp}`);
        } else {
          logSecurityEvent('ws_auth_failed', { ip: clientIp });
          ws.send(JSON.stringify({ type: 'auth:failed', data: { message: 'Invalid session token' } }));
          ws.close(1008, 'Authentication failed');
        }
        return;
      }

      // Require authentication for all other messages
      if (!isAuthenticated) {
        ws.send(JSON.stringify({ type: 'error', data: { message: 'Authentication required' } }));
        return;
      }

      // Handle other message types
      console.log(`[ws] Received: ${msg.type}`);

    } catch (err) {
      console.error('[ws] Error processing message:', err.message);
    }
  });

  ws.on('close', () => {
    console.log(`[ws] Client disconnected from ${clientIp} (total: ${wss.clients.size})`);
    clearTimeout(authTimeout);
  });

  ws.on('error', (err) => {
    console.error(`[ws] Error from ${clientIp}:`, err.message);
    logSecurityEvent('ws_error', { ip: clientIp, error: err.message });
  });
});

function broadcast(msg) {
  const payload = JSON.stringify(msg);
  let sent = 0;
  for (const client of wss.clients) {
    if (client.readyState === 1) {
      client.send(payload);
      sent++;
    }
  }
  return sent;
}

export { broadcast, wss };

// ============================================
// OPENCLAW BRIDGE
// ============================================

const bridge = new OpenClawBridge();

bridge.on('connected', (info) => {
  console.log(`[bridge] Connected (${info.mode} mode)`);
  broadcast({ type: 'bridge:connected', data: info });
});

bridge.on('disconnected', () => {
  broadcast({ type: 'bridge:disconnected' });
});

bridge.on('event', (event) => {
  broadcast(event);
});

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  
  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;
  
  res.status(err.status || 500).json({ error: message });
});

// ============================================
// START SERVER
// ============================================

// Determine bind address
const bindAddress = process.env.BIND_ADDRESS || '127.0.0.1'; // Default to localhost only!

server.listen(config.port, bindAddress, () => {
  const proto = useHttps ? 'https' : 'http';
  console.log('========================================');
  console.log('[server] OpenClaw Command Center SECURE');
  console.log('========================================');
  console.log(`[server] Listening on ${proto}://${bindAddress}:${config.port}`);
  console.log(`[server] TLS: ${useHttps ? 'ENABLED' : 'DISABLED (use reverse proxy!)'}`);
  console.log(`[server] Voice: ${config.openaiApiKey ? 'ENABLED' : 'DISABLED'}`);
  console.log(`[server] Auth: REQUIRED for all API endpoints`);
  console.log(`[server] CORS: ${corsOptions.origin.join(', ')}`);
  console.log('========================================');
  
  if (!useHttps && bindAddress !== '127.0.0.1') {
    console.warn('[server] WARNING: Running HTTP on non-localhost. Use HTTPS or reverse proxy!');
  }
  
  bridge.start();
});
