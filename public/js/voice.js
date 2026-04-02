// Voice recording + playback module
// Tap mascot to record, tap again (or auto-stop) to send to server

let mediaRecorder = null;
let audioChunks = [];
let isRecording = false;
let onTranscription = null; // callback(text)
let silenceTimer = null;
let targetAgent = 'main';
let sessionToken = null;

export function setToken(token) {
  sessionToken = token;
}

const MAX_RECORD_SECONDS = 15;

export function init(opts = {}) {
  onTranscription = opts.onTranscription || null;
}

export function getIsRecording() {
  return isRecording;
}

export function setTargetAgent(agentId) {
  targetAgent = agentId || 'main';
}

export function getTargetAgent() {
  return targetAgent;
}

export async function startRecording() {
  if (isRecording) return;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    audioChunks = [];

    mediaRecorder = new MediaRecorder(stream, {
      mimeType: MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
        ? 'audio/webm;codecs=opus'
        : 'audio/webm',
    });

    mediaRecorder.ondataavailable = (e) => {
      if (e.data.size > 0) audioChunks.push(e.data);
    };

    mediaRecorder.onstop = async () => {
      // Stop all tracks
      stream.getTracks().forEach(t => t.stop());
      clearTimeout(silenceTimer);

      if (audioChunks.length === 0) return;

      const blob = new Blob(audioChunks, { type: 'audio/webm' });
      audioChunks = [];
      await sendToServer(blob);
    };

    mediaRecorder.start(250); // collect in 250ms chunks
    isRecording = true;

    // Auto-stop after max duration
    silenceTimer = setTimeout(() => {
      if (isRecording) stopRecording();
    }, MAX_RECORD_SECONDS * 1000);

  } catch (err) {
    console.error('[voice] Mic access denied:', err);
    isRecording = false;
  }
}

export function stopRecording() {
  if (mediaRecorder && mediaRecorder.state !== 'inactive') {
    mediaRecorder.stop();
  }
  isRecording = false;
}

export async function toggleRecording() {
  if (isRecording) {
    stopRecording();
  } else {
    await startRecording();
  }
  return isRecording;
}

async function sendToServer(blob) {
  const form = new FormData();
  form.append('audio', blob, 'recording.webm');
  form.append('targetAgent', targetAgent);

  // Reset target after sending
  const sentTo = targetAgent;
  targetAgent = 'main';

  try {
    const res = await fetch('/api/voice/transcribe', {
      method: 'POST',
      headers: sessionToken ? { 'Authorization': `Bearer ${sessionToken}` } : {},
      body: form,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Transcription failed');
    }

    const { text } = await res.json();
    if (text && onTranscription) {
      onTranscription(text, sentTo);
    }
  } catch (err) {
    console.error('[voice] Send error:', err);
  }
}

export async function playSpokenResponse(text, agentId = 'main') {
  try {
    const res = await fetch('/api/voice/speak', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(sessionToken ? { 'Authorization': `Bearer ${sessionToken}` } : {}),
      },
      body: JSON.stringify({ text, agent: agentId }),
    });

    if (!res.ok) throw new Error('TTS failed');

    const audioBlob = await res.blob();
    const url = URL.createObjectURL(audioBlob);

    // Use Web Audio API with GainNode for volume boost (Pi has no master mixer)
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const arrayBuffer = await audioBlob.arrayBuffer();
    const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);

    const source = audioCtx.createBufferSource();
    source.buffer = audioBuffer;

    const gainNode = audioCtx.createGain();
    gainNode.gain.value = 2.0; // 2x volume boost

    source.connect(gainNode);
    gainNode.connect(audioCtx.destination);

    return new Promise((resolve) => {
      source.onended = () => {
        URL.revokeObjectURL(url);
        audioCtx.close();
        resolve();
      };
      source.start(0);
    });
  } catch (err) {
    console.error('[voice] Playback error:', err);
  }
}
