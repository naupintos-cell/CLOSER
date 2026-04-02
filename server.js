const express = require('express');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();

// ── SEGURIDAD: body parsing con límite estricto ───────────────────────────────
app.use(express.json({ limit: '32kb' }));

// ── SEGURIDAD: Headers de seguridad HTTP ─────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:;"
  );
  next();
});

// ── SEGURIDAD: CORS estricto ──────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin) return next(); // curl / mismo servidor
  if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  } else {
    return res.status(403).json({ error: 'Origin no permitido' });
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── SEGURIDAD: Rate limiting por capas ───────────────────────────────────────
// Capa 1: límite global (evita DDoS básico)
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minuto
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Esperá un momento.' },
});

// Capa 2: límite por endpoint de generación (protege tu quota de Anthropic)
const genLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,  // 10 minutos
  max: 10,                    // 10 generaciones por IP cada 10 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Límite de generaciones alcanzado. Esperá unos minutos.' },
  skip: (req) => {
    // Skip si tiene API key PRO válida (usuarios pagos no tienen límite)
    const proKey = req.headers['x-pro-key'];
    return proKey && isValidProKey(proKey);
  }
});

app.use('/api/', globalLimiter);
app.use('/api/messages', genLimiter);

// ── UTILIDADES ────────────────────────────────────────────────────────────────
function isValidProKey(key) {
  if (!key || typeof key !== 'string') return false;
  const validKeys = (process.env.PRO_KEYS || '').split(',').map(k => k.trim()).filter(Boolean);
  if (validKeys.length === 0) return false;
  // Comparación en tiempo constante para evitar timing attacks
  return validKeys.some(valid =>
    valid.length === key.length &&
    crypto.timingSafeEqual(Buffer.from(valid), Buffer.from(key))
  );
}

function sanitizeString(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen);
}

// ── VALIDACIÓN ESTRICTA DEL BODY ─────────────────────────────────────────────
const ALLOWED_MODELS = ['claude-sonnet-4-20250514'];
const MAX_TOKENS_CAP = 1000;
const ALLOWED_TOOL_TYPES = ['web_search_20250305'];

function validateBody(body) {
  if (!body || typeof body !== 'object') return 'Body inválido';
  if (!ALLOWED_MODELS.includes(body.model)) return 'Modelo no permitido';
  if (!Array.isArray(body.messages)) return 'messages inválido';
  if (body.messages.length > 8) return 'Demasiados mensajes';
  if ((body.max_tokens ?? 0) > MAX_TOKENS_CAP) return 'max_tokens excede el límite';

  if (body.system && typeof body.system !== 'string') return 'system inválido';
  if (body.system && body.system.length > 3000) return 'system demasiado largo';

  if (body.temperature !== undefined) {
    if (typeof body.temperature !== 'number') return 'temperature inválida';
    if (body.temperature < 0 || body.temperature > 1) return 'temperature fuera de rango';
  }

  for (const m of body.messages) {
    if (!['user', 'assistant'].includes(m.role)) return 'role inválido';
    if (typeof m.content !== 'string' && !Array.isArray(m.content)) return 'content inválido';
    if (typeof m.content === 'string' && m.content.length > 4000) return 'content demasiado largo';
    if (Array.isArray(m.content)) {
      for (const block of m.content) {
        if (!block.type) return 'block sin type';
        if (block.type === 'text' && typeof block.text !== 'string') return 'block text inválido';
        if (block.type === 'text' && block.text.length > 4000) return 'block text demasiado largo';
      }
    }
  }

  // Validar tools si vienen
  if (body.tools) {
    if (!Array.isArray(body.tools)) return 'tools inválido';
    for (const t of body.tools) {
      if (!ALLOWED_TOOL_TYPES.includes(t.type)) return `Tool no permitida: ${t.type}`;
    }
  }

  return null; // OK
}

// ── PROXY HACIA ANTHROPIC ─────────────────────────────────────────────────────
app.post('/api/messages', async (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('[CLOSER] ANTHROPIC_API_KEY no configurada');
    return res.status(500).json({ error: 'Configuración incompleta en el servidor' });
  }

  const validationError = validateBody(req.body);
  if (validationError) {
    console.warn(`[CLOSER] Validación fallida: ${validationError} — IP: ${req.ip}`);
    return res.status(400).json({ error: validationError });
  }

  // Reconstruir payload solo con campos conocidos y saneados
  const payload = {
    model:      req.body.model,
    max_tokens: Math.min(req.body.max_tokens ?? 900, MAX_TOKENS_CAP),
    messages:   req.body.messages,
    ...(req.body.system      && { system:      sanitizeString(req.body.system, 3000) }),
    ...(req.body.temperature !== undefined && { temperature: req.body.temperature }),
    ...(req.body.tools       && { tools: req.body.tools }),
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-beta':    'web-search-2025-03-05',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    const data = await response.json();

    // Log de uso (sin datos sensibles)
    console.log(`[CLOSER] Request OK — status:${response.status} tokens:${data.usage?.output_tokens ?? '?'} ip:${req.ip}`);

    res.status(response.status).json(data);
  } catch (err) {
    if (err.name === 'AbortError') {
      console.error('[CLOSER] Timeout llamando a Anthropic');
      return res.status(504).json({ error: 'Timeout — la API tardó demasiado. Reintentá.' });
    }
    console.error('[CLOSER] Error al llamar Anthropic:', err.message);
    res.status(502).json({ error: 'Error de conexión con la API' });
  }
});

// ── HEALTH CHECK (Railway lo usa para saber si el servicio está vivo) ─────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: Date.now() });
});

// ── FALLBACK SPA ──────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── MANEJO DE ERRORES NO CAPTURADOS ──────────────────────────────────────────
process.on('unhandledRejection', (reason) => {
  console.error('[CLOSER] unhandledRejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[CLOSER] uncaughtException:', err.message);
  process.exit(1);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[CLOSER] Corriendo en puerto ${PORT}`));
