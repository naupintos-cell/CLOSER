const express = require('express');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
app.use(express.json({ limit: '32kb' })); // body máximo 32kb
app.use(express.static(path.join(__dirname, 'public')));

// ── CORS ─────────────────────────────────────────────────────────────────────
// Solo tu dominio puede llamar al proxy
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  // En desarrollo no hay origin (curl, mismo servidor), dejamos pasar
  if (!origin) return next();
  if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  } else {
    return res.status(403).json({ error: 'Origin no permitido' });
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── RATE LIMITING ─────────────────────────────────────────────────────────────
// Máx 10 requests por IP cada 10 minutos
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Esperá unos minutos.' },
});
app.use('/api/', limiter);

// ── VALIDACIÓN ────────────────────────────────────────────────────────────────
const ALLOWED_MODELS  = ['claude-sonnet-4-20250514'];
const MAX_TOKENS_CAP  = 1000;

function validateBody(body) {
  if (!body || typeof body !== 'object') return 'Body inválido';
  if (!ALLOWED_MODELS.includes(body.model))  return 'Modelo no permitido';
  if (!Array.isArray(body.messages))         return 'messages inválido';
  if (body.messages.length > 6)              return 'Demasiados mensajes';
  if ((body.max_tokens ?? 0) > MAX_TOKENS_CAP) return 'max_tokens excede el límite';

  for (const m of body.messages) {
    if (!['user','assistant'].includes(m.role)) return 'role inválido';
    if (typeof m.content !== 'string' && !Array.isArray(m.content)) return 'content inválido';
    if (typeof m.content === 'string' && m.content.length > 4000) return 'content demasiado largo';
  }
  return null; // OK
}

// ── PROXY ─────────────────────────────────────────────────────────────────────
app.post('/api/messages', async (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('ANTHROPIC_API_KEY no configurada');
    return res.status(500).json({ error: 'Configuración incompleta en el servidor' });
  }

  const validationError = validateBody(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  // Reconstruir payload solo con campos conocidos
  const payload = {
    model:       req.body.model,
    max_tokens:  Math.min(req.body.max_tokens ?? 900, MAX_TOKENS_CAP),
    messages:    req.body.messages,
    ...(req.body.system      && { system:      req.body.system }),
    ...(req.body.temperature && { temperature: req.body.temperature }),
    ...(req.body.tools       && { tools:       req.body.tools }),
  };

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-beta':    'web-search-2025-03-05',
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    console.error('Error al llamar Anthropic:', err.message);
    res.status(502).json({ error: 'Error de conexión con la API' });
  }
});

// ── FALLBACK SPA ──────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Closer corriendo en puerto ${PORT}`));
