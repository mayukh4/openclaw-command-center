import * as terminal from './terminal.js';
import * as mascot from './mascot.js';
import * as office from './office.js';
import * as voice from './voice.js';

// --- Init ---

terminal.init('terminal-output');
mascot.init('mascot-canvas');
office.init('office-canvas');

voice.init({
  onTranscription: (text, agent) => {
    terminal.log(`[you → ${agent || 'main'}] ${text}`, 'agent', true);
    mascot.setEmotion('thinking');
  },
});

// --- Fullscreen on first interaction ---

let isFullscreen = false;

async function requestFullscreen() {
  if (isFullscreen) return;
  try {
    const el = document.documentElement;
    if (el.requestFullscreen) {
      await el.requestFullscreen();
    } else if (el.webkitRequestFullscreen) {
      await el.webkitRequestFullscreen();
    }
    isFullscreen = true;
  } catch (err) {
    console.log('[fullscreen] Request denied:', err.message);
  }
}

document.addEventListener('fullscreenchange', () => {
  isFullscreen = !!document.fullscreenElement;
});

document.addEventListener('click', () => {
  if (!isFullscreen) requestFullscreen();
}, { once: false });

// --- Mascot tap = voice toggle (always targets 'main') ---

const mascotZone = document.getElementById('zone-mascot');

mascotZone.addEventListener('click', async (e) => {
  if (!isFullscreen) {
    await requestFullscreen();
    await new Promise(r => setTimeout(r, 300));
  }

  voice.setTargetAgent('main');
  const recording = await voice.toggleRecording();
  if (recording) {
    mascot.setEmotion('listening');
    office.onVoiceStart('main'); // all agents look up
    terminal.log('[mic] Listening for Jansky... tap to stop', 'system', true);
  } else {
    mascot.setEmotion('thinking');
    terminal.log('[mic] Processing...', 'system', true);
  }
});

// --- Office Canvas: Tap agent to toggle recording for that agent ---

const officeCanvas = document.getElementById('office-canvas');
let activeOfficeAgent = null; // which agent we're currently recording for

officeCanvas.addEventListener('click', async (e) => {
  const rect = officeCanvas.getBoundingClientRect();
  const x = e.clientX - rect.left;
  const y = e.clientY - rect.top;

  const agentId = office.getAgentAtPoint(x, y);
  if (!agentId) return;

  if (!isFullscreen) {
    await requestFullscreen();
    await new Promise(r => setTimeout(r, 300));
  }

  // If already recording for this agent, stop
  if (voice.getIsRecording() && activeOfficeAgent === agentId) {
    voice.stopRecording();
    office.setAgentHighlight(agentId, false);
    activeOfficeAgent = null;
    mascot.setEmotion('thinking');
    terminal.log('[mic] Processing...', 'system', true);
    return;
  }

  // If recording for a different agent, stop that first
  if (voice.getIsRecording() && activeOfficeAgent) {
    voice.stopRecording();
    office.setAgentHighlight(activeOfficeAgent, false);
    // small delay before starting new recording
    await new Promise(r => setTimeout(r, 200));
  }

  // Start recording for this agent
  activeOfficeAgent = agentId;
  voice.setTargetAgent(agentId);
  office.setAgentHighlight(agentId, true);
  office.onVoiceStart(agentId); // all agents look up
  await voice.startRecording();
  mascot.setEmotion('listening');
  terminal.log(`[mic] Listening for ${agentId}... tap again to send`, 'system', true);
});

// --- Boot Sequence ---

const BOOT_LINES = [
  ['[sys] OpenClaw Command Center v1.0', 'system'],
  ['[sys] Initializing display modules...', 'system'],
  ['[sys] Mascot renderer: OK', 'info'],
  ['[sys] Office renderer: OK (3 agents)', 'info'],
  ['[sys] Terminal: OK', 'info'],
  ['[sys] Voice: tap mascot for Jansky, tap agent in office', 'agent'],
  ['[sys] Agents: main(Jansky) | claw-1(Coder) | claw-2(Research)', 'info'],
  ['[sys] Connecting to OpenClaw gateway...', 'system'],
];

let bootIndex = 0;
function bootSequence() {
  if (bootIndex < BOOT_LINES.length) {
    const [text, type] = BOOT_LINES[bootIndex];
    terminal.log(text, type, true);
    bootIndex++;
    setTimeout(bootSequence, 300 + Math.random() * 200);
  }
}

bootSequence();

// --- WebSocket Connection ---

let ws = null;
let reconnectTimer = null;

function connect() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${protocol}//${location.host}`;

  ws = new WebSocket(url);

  ws.onopen = async () => {
    terminal.log('[ws] Connected to server', 'info');
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    try {
      const resp = await fetch('/api/auth/local-token');
      if (resp.ok) {
        const { token } = await resp.json();
        ws.send(JSON.stringify({ type: 'auth', token }));
        voice.setToken(token);
        office.setToken(token);
      } else {
        console.error('[ws] Failed to fetch local token:', resp.status);
      }
    } catch (err) {
      console.error('[ws] Failed to fetch local token:', err);
    }
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleEvent(msg);
    } catch (err) {
      console.error('Failed to parse message:', err);
    }
  };

  ws.onclose = () => {
    terminal.log('[ws] Disconnected, reconnecting...', 'error');
    scheduleReconnect();
  };

  ws.onerror = () => {};
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, 2000);
}

connect();

// --- Event Router ---

const EVENT_TO_EMOTION = {
  'agent:idle': 'idle',
  'agent:listening': 'listening',
  'agent:thinking': 'thinking',
  'agent:tool_use': 'working',
  'agent:responding': 'happy',
  'agent:error': 'error',
};

const EVENT_TO_OFFICE_STATE = {
  'agent:idle': 'idle',
  'agent:listening': 'idle',
  'agent:thinking': 'thinking',
  'agent:tool_use': 'working',
  'agent:responding': 'talking',
  'agent:error': 'idle',
};

const EVENT_TO_LOG_TYPE = {
  'agent:idle': 'info',
  'agent:listening': 'agent',
  'agent:thinking': 'agent',
  'agent:tool_use': 'tool',
  'agent:responding': 'agent',
  'agent:error': 'error',
};

async function handleEvent(msg) {
  const { type, data } = msg;

  // Status messages
  if (type === 'status' || type === 'bridge:connected') {
    const mode = data?.mode || 'unknown';
    terminal.log(`[bridge] Mode: ${mode}`, 'system', true);
    if (data?.voiceEnabled) {
      terminal.log('[voice] OpenAI voice enabled', 'info');
    }
    return;
  }

  if (type === 'bridge:disconnected') {
    terminal.log('[bridge] Gateway disconnected', 'error');
    mascot.setEmotion('error');
    return;
  }

  if (type === 'voice:transcription') {
    return;
  }

  // Agent responding — speak with agent-specific voice
  if (type === 'agent:responding' && data?.message) {
    const agentId = data.agent || 'main';
    mascot.setEmotion('happy');
    terminal.log(formatLogEntry(type, data), 'agent', true);
    office.setAgentState(agentId, 'talking', data);

    // Clear highlight if we were recording for this agent
    if (activeOfficeAgent === agentId) {
      office.setAgentHighlight(agentId, false);
      activeOfficeAgent = null;
    }

    voice.playSpokenResponse(data.message, agentId).then(() => {
      mascot.setEmotion('idle');
      office.onTaskComplete(agentId); // celebration animation
      office.setAgentState(agentId, 'idle', {});
    });
    return;
  }

  // Agent events
  const emotion = EVENT_TO_EMOTION[type];
  if (emotion) {
    mascot.setEmotion(emotion);
  }

  const officeState = EVENT_TO_OFFICE_STATE[type];
  if (officeState && data?.agent) {
    office.setAgentState(data.agent, officeState, data);
  }

  const logType = EVENT_TO_LOG_TYPE[type];
  if (logType) {
    const text = formatLogEntry(type, data);
    terminal.log(text, logType, true);
  }
}

function formatLogEntry(type, data) {
  const agent = data?.agent || '?';
  const shortType = type.split(':')[1] || type;

  switch (type) {
    case 'agent:tool_use':
      return `[${agent}] ${shortType}: ${data.tool || '?'}(${data.input || ''})`;
    case 'agent:responding':
      return `[${agent}] ${data.message || 'responding...'}`;
    case 'agent:error':
      return `[${agent}] ERROR: ${data.message || data.status || 'unknown'}`;
    default:
      return `[${agent}] ${data.status || shortType}`;
  }
}

// --- Render Loop ---

let lastTime = performance.now();

function frame(now) {
  const dt = now - lastTime;
  lastTime = now;

  mascot.update(dt);
  office.update(dt);

  mascot.draw();
  office.draw();

  requestAnimationFrame(frame);
}

requestAnimationFrame(frame);
