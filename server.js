/**
 * CLOSER. — Server PRO
 * Stack: Express + Supabase + Anthropic + Mercado Pago
 */

'use strict';

const express     = require('express');
const rateLimit   = require('express-rate-limit');
const path        = require('path');
const crypto      = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ── Trust proxy (Railway usa reverse proxy) ───────────────────────────────────
app.set('trust proxy', 1);

// ── ENV vars ──────────────────────────────────────────────────────────────────
const {
  ANTHROPIC_API_KEY,
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  MP_ACCESS_TOKEN,
  MP_WEBHOOK_SECRET,
  ALLOWED_ORIGINS,
  PORT = 3000,
} = process.env;

// ── Supabase (service role — solo en server) ──────────────────────────────────
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

// ── Body parsing ───────────────────────────────────────────────────────────────
// Webhook de MP necesita raw body para verificar firma
app.use('/api/mp/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '64kb' }));

// ── Security headers ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ── CORS ──────────────────────────────────────────────────────────────────────
const allowedOrigins = (ALLOWED_ORIGINS || '')
  .split(',').map(o => o.trim()).filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  // Sin origin = same-origin o server-to-server → OK
  if (!origin) return next();
  // Si no hay lista configurada, o el origin está en la lista → OK
  if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Vary', 'Origin');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    return next();
  }
  // Railway internal URLs también permitidas
  if (origin.includes('railway.app') || origin.includes('up.railway.app')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    return next();
  }
  return res.status(403).json({ error: 'Origin no permitido' });
});

// ── Rate limiting ─────────────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, max: 200,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Esperá un momento.' }
});
const genLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 4, // Tier 1 de Anthropic = ~5 RPM; dejamos margen para no llegar al límite
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Demasiadas generaciones por minuto. Esperá unos segundos y reintentá.' },
});

app.use('/api/', globalLimiter);

// ── Auth helper ───────────────────────────────────────────────────────────────
async function getUserFromRequest(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    console.warn('[CLOSER] auth: no Bearer header');
    return null;
  }
  const token = authHeader.slice(7);
  console.log('[CLOSER] auth: token prefix =', token.slice(0, 30));
  console.log('[CLOSER] auth: SUPABASE_URL =', SUPABASE_URL ? 'OK' : 'MISSING');
  console.log('[CLOSER] auth: SUPABASE_SERVICE_KEY =', SUPABASE_SERVICE_KEY ? SUPABASE_SERVICE_KEY.slice(0, 20) + '...' : 'MISSING');
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error) {
      console.warn('[CLOSER] auth getUser error:', error.message);
      return null;
    }
    if (!user) {
      console.warn('[CLOSER] auth: user null');
      return null;
    }
    console.log('[CLOSER] auth: user OK =', user.email);
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();
    if (profileError) console.warn('[CLOSER] auth profile error:', profileError.message);
    if (!profile) console.warn('[CLOSER] auth: profile null for', user.email);
    return profile || null;
  } catch (e) {
    console.error('[CLOSER] auth exception:', e.message);
    return null;
  }
}

// ── Validación body ───────────────────────────────────────────────────────────
const ALLOWED_MODELS = ['claude-sonnet-4-20250514'];
const MAX_TOKENS_CAP = 1000;

function validateBody(body) {
  if (!body || typeof body !== 'object') return 'Body inválido';
  if (!ALLOWED_MODELS.includes(body.model))  return 'Modelo no permitido';
  if (!Array.isArray(body.messages))         return 'messages inválido';
  if (body.messages.length > 8)              return 'Demasiados mensajes';
  if ((body.max_tokens ?? 0) > MAX_TOKENS_CAP) return 'max_tokens excede el límite';
  if (body.system && body.system.length > 4000) return 'system demasiado largo';
  if (body.temperature !== undefined) {
    if (typeof body.temperature !== 'number') return 'temperature inválida';
    if (body.temperature < 0 || body.temperature > 1) return 'temperature fuera de rango';
  }
  for (const m of body.messages) {
    if (!['user','assistant'].includes(m.role)) return 'role inválido';
    const content = m.content;
    if (typeof content !== 'string' && !Array.isArray(content)) return 'content inválido';
    if (typeof content === 'string' && content.length > 5000) return 'content demasiado largo';
  }
  if (body.tools) {
    if (!Array.isArray(body.tools)) return 'tools inválido';
    const allowed = ['web_search_20250305'];
    for (const t of body.tools) {
      if (!allowed.includes(t.type)) return `Tool no permitida: ${t.type}`;
    }
  }
  return null;
}

// ── Anthropic fetch helper con retry en 429 ───────────────────────────────────
async function callAnthropic(payload, { maxRetries = 3, baseDelay = 8000 } = {}) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 40000);
    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type':      'application/json',
          'x-api-key':         ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
          'anthropic-beta':    'web-search-2025-03-05',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      // Si es 429, reintentamos con backoff exponencial
      if (response.status === 429 && attempt < maxRetries) {
        // Respetar el header Retry-After si viene en la respuesta
        const retryAfter = response.headers.get('retry-after');
        const delay = retryAfter
          ? parseInt(retryAfter, 10) * 1000
          : baseDelay * Math.pow(2, attempt); // 8s, 16s, 32s
        console.warn(`[CLOSER] 429 rate limit — reintento ${attempt + 1}/${maxRetries} en ${delay / 1000}s`);
        await new Promise(r => setTimeout(r, delay));
        continue;
      }

      return { response, data: await response.json() };
    } catch (err) {
      clearTimeout(timeout);
      if (err.name === 'AbortError') throw err; // timeout — no reintentar
      if (attempt < maxRetries) {
        const delay = baseDelay * Math.pow(2, attempt);
        console.warn(`[CLOSER] Error de red — reintento ${attempt + 1}/${maxRetries} en ${delay / 1000}s:`, err.message);
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw err;
    }
  }
}

// ── GET /api/profile — perfil del usuario autenticado ────────────────────────
app.get('/api/profile', async (req, res) => {
  const user = await getUserFromRequest(req);
  if (!user) return res.status(401).json({ error: 'No autenticado' });
  res.json({ user });
});

// ── GET /api/dashboard — historial y métricas PRO ────────────────────────────
app.get('/api/dashboard', async (req, res) => {
  const user = await getUserFromRequest(req);
  if (!user) return res.status(401).json({ error: 'No autenticado' });
  if (user.plan !== 'pro') return res.status(403).json({ error: 'Requiere plan PRO' });

  try {
    // Últimas 20 generaciones
    const { data: generations } = await supabase
      .from('generations')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(20);

    // Resultados de mensajes
    const { data: results } = await supabase
      .from('message_results')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(100);

    // Métricas
    const total   = results?.length || 0;
    const closed  = results?.filter(r => r.result === 'closed').length || 0;
    const ratio   = total > 0 ? Math.round((closed / total) * 100) : 0;

    // Mensajes con más cierres (top 3)
    const byType = {};
    for (const r of (results || [])) {
      if (!byType[r.msg_type]) byType[r.msg_type] = { closed: 0, total: 0 };
      byType[r.msg_type].total++;
      if (r.result === 'closed') byType[r.msg_type].closed++;
    }

    res.json({
      user,
      generations: generations || [],
      results: results || [],
      metrics: { total, closed, lost: total - closed, ratio },
      byType,
    });
  } catch (err) {
    console.error('[CLOSER] dashboard error:', err.message);
    res.status(500).json({ error: 'Error al cargar dashboard' });
  }
});

// ── POST /api/result — guardar resultado de un mensaje ───────────────────────
app.post('/api/result', async (req, res) => {
  const user = await getUserFromRequest(req);
  if (!user) return res.status(401).json({ error: 'No autenticado' });

  const { generation_id, msg_type, msg_text, result, notes } = req.body;
  if (!generation_id || !msg_type || !msg_text || !result) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }
  const validTypes   = ['inicio','precio','duda','reactivacion','cierre'];
  const validResults = ['closed','lost','pending'];
  if (!validTypes.includes(msg_type))   return res.status(400).json({ error: 'msg_type inválido' });
  if (!validResults.includes(result))   return res.status(400).json({ error: 'result inválido' });

  try {
    const { error } = await supabase.from('message_results').insert({
      user_id: user.id,
      generation_id,
      msg_type,
      msg_text: msg_text.slice(0, 2000),
      result,
      notes: notes?.slice(0, 500) || null,
    });
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error('[CLOSER] result insert error:', err.message);
    res.status(500).json({ error: 'Error al guardar resultado' });
  }
});

// ── POST /api/messages — generación con Claude ────────────────────────────────
app.post('/api/messages', genLimiter, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Configuración incompleta en el servidor' });
  }

  // Verificar usuario (puede ser anon o autenticado)
  const user = await getUserFromRequest(req);
  const isPro = user?.plan === 'pro';

  // Validar body
  const validationError = validateBody(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  // Construir historial de aprendizaje para usuarios PRO
  let learningContext = '';
  if (isPro && user) {
    try {
      const { data: results } = await supabase
        .from('message_results')
        .select('msg_type, msg_text, result')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(30);

      if (results && results.length > 0) {
        const wins = results.filter(r => r.result === 'closed').slice(0, 5);
        const losses = results.filter(r => r.result === 'lost').slice(0, 5);

        if (wins.length > 0 || losses.length > 0) {
          learningContext = '\n\nHISTORIAL DE ESTE VENDEDOR (usalo para calibrar el tono):';
          if (wins.length > 0) {
            learningContext += '\nMensajes que CERRARON VENTAS para este usuario:\n';
            wins.forEach(w => { learningContext += `- [${w.msg_type}]: "${w.msg_text.slice(0, 150)}"\n`; });
          }
          if (losses.length > 0) {
            learningContext += '\nMensajes que NO funcionaron:\n';
            losses.forEach(l => { learningContext += `- [${l.msg_type}]: "${l.msg_text.slice(0, 150)}"\n`; });
          }
          learningContext += '\nAdaptá el estilo y tono según estos patrones reales del vendedor.';
        }
      }
    } catch (e) {
      console.warn('[CLOSER] No se pudo cargar historial:', e.message);
    }
  }

  // Inyectar contexto de aprendizaje al system prompt si existe
  const payload = {
    model:      req.body.model,
    max_tokens: Math.min(req.body.max_tokens ?? 900, MAX_TOKENS_CAP),
    messages:   req.body.messages,
    ...(req.body.system && {
      system: req.body.system + learningContext
    }),
    ...(req.body.temperature !== undefined && { temperature: req.body.temperature }),
    ...(req.body.tools && { tools: req.body.tools }),
  };

  try {
    const { response, data } = await callAnthropic(payload);

    // Log
    console.log(`[CLOSER] gen OK — plan:${isPro?'pro':'free'} tokens:${data.usage?.output_tokens ?? '?'} ip:${req.ip}`);

    // Guardar generación en DB si el usuario está autenticado
    // (el frontend manda los datos del form en req.body._form)
    if (user && req.body._form) {
      const form = req.body._form;
      // Extraer mensajes generados para guardarlos
      // (se guarda async, no bloqueamos la respuesta)
      saveGeneration(user.id, form, data, isPro).catch(e =>
        console.warn('[CLOSER] saveGeneration error:', e.message)
      );
    }

    res.status(response.status).json(data);
  } catch (err) {
    if (err.name === 'AbortError') {
      return res.status(504).json({ error: 'Timeout — la API tardó demasiado. Reintentá.' });
    }
    console.error('[CLOSER] Anthropic error:', err.message);
    res.status(502).json({ error: 'Error de conexión con la API' });
  }
});

// ── Guardar generación en DB (async, no bloquea) ──────────────────────────────
async function saveGeneration(userId, form, anthropicData, isPro) {
  // Extraer texto de los bloques de Claude
  const textBlocks = (anthropicData.content || []).filter(b => b.type === 'text');
  if (!textBlocks.length) return;

  let messages;
  try {
    const txt = textBlocks[textBlocks.length - 1].text.trim()
      .replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
    messages = JSON.parse(txt);
  } catch { return; }

  if (!messages?.inicio || !messages?.precio || !messages?.duda) return;

  await supabase.from('generations').insert({
    user_id:        userId,
    negocio:        (form.negocio || '').slice(0, 500),
    cliente:        (form.cliente || '').slice(0, 500),
    problema:       (form.problema || '').slice(0, 500),
    objecion:       (form.objecion || '').slice(0, 300),
    precio:         (form.precio || '').slice(0, 200),
    market_context: form.marketCtx || null,
    msg_inicio:     messages.inicio.slice(0, 2000),
    msg_precio:     messages.precio.slice(0, 2000),
    msg_duda:       messages.duda.slice(0, 2000),
    plan_at_gen:    isPro ? 'pro' : 'free',
  });

  // Actualizar contador en profile
  await supabase.from('profiles')
    .update({ total_gens: supabase.rpc('increment', { x: 1 }) })
    .eq('id', userId);
}

// ── POST /api/mp/webhook — webhooks de Mercado Pago ──────────────────────────
app.post('/api/mp/webhook', async (req, res) => {
  // Verificar firma de MP
  const signature = req.headers['x-signature'];
  const requestId = req.headers['x-request-id'];

  if (MP_WEBHOOK_SECRET && signature) {
    try {
      const parts = signature.split(',');
      const ts   = parts.find(p => p.startsWith('ts='))?.split('=')[1];
      const v1   = parts.find(p => p.startsWith('v1='))?.split('=')[1];
      const rawBody = req.body.toString();
      const manifest = `id:${req.query.id};request-id:${requestId};ts:${ts};`;
      const hmac = crypto.createHmac('sha256', MP_WEBHOOK_SECRET)
        .update(manifest).digest('hex');
      if (hmac !== v1) {
        console.warn('[CLOSER] MP webhook firma inválida');
        return res.status(401).json({ error: 'Firma inválida' });
      }
    } catch (e) {
      console.error('[CLOSER] MP webhook verificación error:', e.message);
    }
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString());
  } catch {
    return res.status(400).json({ error: 'JSON inválido' });
  }

  // Guardar webhook en DB para auditoría
  await supabase.from('mp_webhooks').insert({
    mp_id:   payload.id?.toString(),
    type:    payload.type,
    action:  payload.action,
    payload: payload,
  }).catch(e => console.warn('[CLOSER] webhook save error:', e.message));

  // Procesar según tipo
  try {
    if (payload.type === 'subscription_preapproval') {
      await processMPSubscription(payload);
    } else if (payload.type === 'payment') {
      await processMPPayment(payload);
    }
  } catch (e) {
    console.error('[CLOSER] webhook process error:', e.message);
  }

  // Siempre responder 200 a MP (sino reintenta indefinidamente)
  res.sendStatus(200);
});

// ── Procesar suscripción de MP ────────────────────────────────────────────────
async function processMPSubscription(payload) {
  const subId  = payload.data?.id;
  const action = payload.action;
  if (!subId) return;

  // Consultar estado real de la suscripción en MP
  const mpRes = await fetch(`https://api.mercadopago.com/preapproval/${subId}`, {
    headers: { 'Authorization': `Bearer ${MP_ACCESS_TOKEN}` }
  });
  const sub = await mpRes.json();

  const email  = sub.payer_email;
  const status = sub.status; // authorized, paused, cancelled

  if (!email) return;

  // Buscar usuario por email
  const { data: profile } = await supabase
    .from('profiles')
    .select('id')
    .eq('email', email)
    .single();

  if (!profile) {
    console.warn(`[CLOSER] MP webhook: usuario no encontrado para ${email}`);
    return;
  }

  if (status === 'authorized') {
    // Activar PRO — 31 días desde hoy
    const proUntil = new Date();
    proUntil.setDate(proUntil.getDate() + 31);

    await supabase.from('profiles').update({
      plan:               'pro',
      pro_since:          new Date().toISOString(),
      pro_until:          proUntil.toISOString(),
      mp_subscription_id: subId,
      mp_customer_id:     sub.payer_id?.toString(),
    }).eq('id', profile.id);

    console.log(`[CLOSER] PRO activado para ${email}`);

  } else if (['cancelled', 'paused'].includes(status)) {
    await supabase.from('profiles').update({
      plan: 'free',
    }).eq('id', profile.id);

    console.log(`[CLOSER] PRO cancelado/pausado para ${email} — status: ${status}`);
  }

  // Marcar webhook como procesado
  await supabase.from('mp_webhooks')
    .update({ processed: true })
    .eq('mp_id', payload.data?.id?.toString());
}

// ── Procesar pago de MP (pagos únicos si los usás) ────────────────────────────
async function processMPPayment(payload) {
  const paymentId = payload.data?.id;
  if (!paymentId) return;

  const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
    headers: { 'Authorization': `Bearer ${MP_ACCESS_TOKEN}` }
  });
  const payment = await mpRes.json();

  if (payment.status !== 'approved') return;

  const email = payment.payer?.email;
  if (!email) return;

  const { data: profile } = await supabase
    .from('profiles').select('id').eq('email', email).single();
  if (!profile) return;

  // Extender PRO 31 días
  const { data: current } = await supabase
    .from('profiles').select('pro_until').eq('id', profile.id).single();

  const base = current?.pro_until ? new Date(current.pro_until) : new Date();
  if (base < new Date()) base.setTime(new Date().getTime());
  base.setDate(base.getDate() + 31);

  await supabase.from('profiles').update({
    plan:      'pro',
    pro_since: new Date().toISOString(),
    pro_until: base.toISOString(),
  }).eq('id', profile.id);

  console.log(`[CLOSER] Pago procesado para ${email} — PRO hasta ${base.toISOString()}`);
}

// ── POST /api/mp/create-subscription — crear link de suscripción ─────────────
app.post('/api/mp/create-subscription', async (req, res) => {
  const user = await getUserFromRequest(req);
  if (!user) return res.status(401).json({ error: 'No autenticado' });
  if (!MP_ACCESS_TOKEN) return res.status(500).json({ error: 'MP no configurado' });

  try {
    const backUrl = process.env.APP_URL || 'https://closer-production-9f2d.up.railway.app';

    console.log('[CLOSER] MP token length:', MP_ACCESS_TOKEN?.length, 'first10:', MP_ACCESS_TOKEN?.slice(0,10), 'last10:', MP_ACCESS_TOKEN?.slice(-10));
    const mpRes = await fetch('https://api.mercadopago.com/preapproval_plan', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${MP_ACCESS_TOKEN}`,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify({
        reason:           'CLOSER. PRO — Sistema de ventas',
        auto_recurring: {
          frequency:       1,
          frequency_type: 'months',
          transaction_amount: 54900,
          currency_id:    'ARS',
        },
        back_url: `${backUrl}/dashboard`,
        payer_email: user.email,
        external_reference: user.id,
      })
    });

    const plan = await mpRes.json();
    console.log('[CLOSER] MP plan response:', JSON.stringify(plan));
    if (!plan.id) throw new Error(plan.message || 'Error creando plan MP');

    // El init_point del plan ya es suficiente para que el usuario se suscriba
    if (!plan.init_point) throw new Error('No se obtuvo init_point del plan MP');

    res.json({ checkout_url: plan.init_point, subscription_id: plan.id });
  } catch (err) {
    console.error('[CLOSER] MP create-subscription error:', err.message);
    res.status(500).json({ error: 'Error al crear suscripción: ' + err.message });
  }
});

// ── POST /api/generate — proxy a Anthropic ───────────────────────────────────
app.post('/api/generate', genLimiter, async (req, res) => {
  const validationError = validateBody(req.body);
  if (validationError) return res.status(400).json({ error: validationError });

  try {
    const { response, data } = await callAnthropic(req.body);
    return res.status(response.status).json(data);
  } catch (err) {
    if (err.name === 'AbortError') return res.status(504).json({ error: 'Timeout' });
    console.error('[CLOSER] /api/generate error:', err.message);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// ── Health check ───────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: Date.now() });
});

// ── Static + SPA fallback ─────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Error handlers ────────────────────────────────────────────────────────────
process.on('unhandledRejection', reason => {
  console.error('[CLOSER] unhandledRejection:', reason);
});
process.on('uncaughtException', err => {
  console.error('[CLOSER] uncaughtException:', err.message);
  process.exit(1);
});

app.listen(PORT, () => console.log(`[CLOSER] PRO corriendo en puerto ${PORT}`));
