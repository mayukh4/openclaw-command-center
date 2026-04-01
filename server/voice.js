import OpenAI from 'openai';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import config from './config.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

let openai = null;

function getClient() {
  if (!openai) {
    if (!config.openaiApiKey) {
      throw new Error('OPENAI_API_KEY not set in .env');
    }
    openai = new OpenAI({ apiKey: config.openaiApiKey });
  }
  return openai;
}

export async function transcribe(audioBuffer, filename = 'audio.webm') {
  const client = getClient();
  const file = new File([audioBuffer], filename, { type: 'audio/webm' });

  const result = await client.audio.transcriptions.create({
    model: 'whisper-1',
    file,
  });

  return result.text;
}

// Agent → voice mapping — loaded from config/ui.json if present, else defaults
const DEFAULT_VOICES = { 'main': 'onyx', 'claw-1': 'echo', 'claw-2': 'fable' };

function loadAgentVoices() {
  const configPath = join(__dirname, '..', 'config', 'ui.json');
  if (existsSync(configPath)) {
    try {
      const parsed = JSON.parse(readFileSync(configPath, 'utf8'));
      const voices = { ...DEFAULT_VOICES };
      for (const agentId of ['main', 'claw-1', 'claw-2']) {
        const v = parsed.agents?.[agentId]?.voice;
        if (v && typeof v === 'string') voices[agentId] = v;
      }
      return voices;
    } catch (err) {
      console.warn('[voice] Failed to parse config/ui.json, using default voices:', err.message);
    }
  }
  return DEFAULT_VOICES;
}

const AGENT_VOICES = loadAgentVoices();

export async function speak(text, agentId = 'main') {
  const client = getClient();
  const voice = AGENT_VOICES[agentId] || 'nova';

  const response = await client.audio.speech.create({
    model: 'tts-1',
    voice,
    input: text,
    response_format: 'mp3',
  });

  const arrayBuffer = await response.arrayBuffer();
  return Buffer.from(arrayBuffer);
}
