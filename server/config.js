/**
 * OpenClaw Command Center - Secure Configuration
 * 
 * All sensitive values are loaded from environment variables.
 * Never hardcode secrets in this file!
 */

import 'dotenv/config';

const config = {
  // Server configuration
  port: parseInt(process.env.PORT || '3000', 10),
  bindAddress: process.env.BIND_ADDRESS || '127.0.0.1',
  trustProxy: process.env.TRUST_PROXY === 'true',
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // CORS configuration
  corsOrigins: process.env.CORS_ORIGINS 
    ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
    : ['http://localhost:3000'],
  
  // OpenClaw Gateway
  gatewayUrl: process.env.GATEWAY_URL || 'ws://127.0.0.1:18789',
  gatewayToken: process.env.GATEWAY_TOKEN || '',
  demoMode: process.env.DEMO_MODE !== 'false',
  
  // OpenAI API (for voice features)
  openaiApiKey: process.env.OPENAI_API_KEY || '',
  
  // Weather widget
  weatherLocation: process.env.WEATHER_LOCATION || 'Kingston,Ontario,Canada',
  
  // Rate limiting (can be overridden via env)
  rateLimit: {
    general: parseInt(process.env.RATE_LIMIT_GENERAL || '120', 10),
    voice: parseInt(process.env.RATE_LIMIT_VOICE || '20', 10),
  },
  
  // Logging
  logLevel: process.env.LOG_LEVEL || 'info',
  
  // Validation helpers
  get isProduction() {
    return this.nodeEnv === 'production';
  },
  
  get hasApiKeys() {
    return (process.env.API_KEYS || '').split(',').some(k => k.trim().length > 0);
  },
  
  get hasOpenAI() {
    return this.openaiApiKey.length > 0;
  },
};

// Validate required configuration
function validateConfig() {
  const warnings = [];
  
  if (!config.hasApiKeys) {
    warnings.push('API_KEYS not configured - authentication will fail!');
  }
  
  if (config.bindAddress !== '127.0.0.1' && config.nodeEnv === 'production') {
    warnings.push(`BIND_ADDRESS=${config.bindAddress} - ensure you have proper firewall/reverse proxy!`);
  }
  
  if (!config.trustProxy && config.nodeEnv === 'production') {
    warnings.push('TRUST_PROXY not set - rate limiting may not work correctly behind proxy');
  }
  
  if (warnings.length > 0) {
    console.warn('\n[config] ⚠️  Configuration warnings:');
    warnings.forEach(w => console.warn(`[config]   - ${w}`));
    console.warn('');
  }
  
  return warnings;
}

// Run validation on load
validateConfig();

export default config;
