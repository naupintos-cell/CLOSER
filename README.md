# CLOSER. — Deploy en Railway

## Estructura
```
closer-app/
├── server.js          ← proxy Express (protege la API key)
├── package.json
├── railway.toml
├── .gitignore
└── public/
    └── index.html     ← tu landing page
```

---

## Deploy paso a paso

### 1. Subir a GitHub

```bash
# Desde la carpeta del proyecto
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/closer-app.git
git push -u origin main
```

### 2. Crear proyecto en Railway

1. Entrá a [railway.app](https://railway.app) y logueate
2. **New Project** → **Deploy from GitHub repo**
3. Seleccioná el repo `closer-app`
4. Railway va a detectar Node.js automáticamente y hacer el deploy

### 3. Agregar la variable de entorno (¡MUY IMPORTANTE!)

En Railway, dentro de tu proyecto:
1. Click en el servicio → pestaña **Variables**
2. Agregar variable:
   - **Name:** `ANTHROPIC_API_KEY`
   - **Value:** `sk-ant-...` (tu API key real)
3. Railway reinicia el servicio automáticamente

### 4. Dominio

- Railway te da un dominio gratis tipo `closer-app.up.railway.app`
- O podés configurar tu dominio custom en Settings → Domains

---

## Variables de entorno necesarias

| Variable | Descripción |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Tu API key de Anthropic (obligatoria) |
| `PORT` | Railway la setea solo, no hace falta |

---

## Desarrollo local

```bash
npm install

# Crear archivo .env con tu API key
echo "ANTHROPIC_API_KEY=sk-ant-tu-key-aqui" > .env

# Instalar dotenv para leer el .env
npm install dotenv

# Agregar al inicio de server.js: require('dotenv').config()
node server.js
# → http://localhost:3000
```

---

## ¿Por qué el proxy?

Sin el proxy, la API key queda expuesta en el HTML y cualquiera puede verla en DevTools y usarla. Con este proxy, la key vive solo en Railway como variable de entorno, nunca llega al browser.
