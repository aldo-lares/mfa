const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const port = Number(process.env.PORT || 3000);
const soapUrl = process.env.SOAP_URL || 'http://localhost:8080/auth';
const index = fs.readFileSync(path.join(__dirname, 'index.html'));
const crypto = require('node:crypto');
const session = require('express-session');
const { ConfidentialClientApplication, CryptoProvider } = require('@azure/msal-node');

const redirectUri = process.env.ENTRA_REDIRECT_URI || `http://localhost:${port}/auth/callback`;
const tenantId = process.env.ENTRA_TENANT_ID;
const clientId = process.env.ENTRA_CLIENT_ID;
const clientSecret = process.env.ENTRA_CLIENT_SECRET;
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const scopes = ['openid', 'profile', 'email'];
const cryptoProvider = new CryptoProvider();

const msalClient = tenantId && clientId && clientSecret
  ? new ConfidentialClientApplication({
      auth: {
        clientId,
        authority: `https://login.microsoftonline.com/${tenantId}`,
        clientSecret
      }
    })
  : null;

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(session({
  name: 'mfa.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 1000
  }
}));

function requireMsal(response) {
  if (msalClient) return true;
  response.status(503).json({ message: 'La autenticación con Microsoft Entra no está configurada.' });
  return false;
}

app.get('/', (_request, response) => {
  response.type('html').send(index);
});

app.post('/api/authenticate', async (request, response, next) => {
  try {
    const user = typeof request.body.user === 'string' ? request.body.user.trim() : '';
    const password = typeof request.body.password === 'string' ? request.body.password : '';
    if (!user || !password) {
      return response.status(400).json({ message: 'Usuario y contraseña son obligatorios.' });
    }

    const result = await authenticateLdap(user, password);
    response.json({ ...result, user });
  } catch (error) {
    next(error);
  }
});

app.get('/auth/entra/login', async (request, response, next) => {
  if (!requireMsal(response)) return;
  try {
    const { verifier, challenge } = await cryptoProvider.generatePkceCodes();
    const state = crypto.randomBytes(32).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    request.session.entraFlow = { verifier, state, nonce };

    const authUrl = await msalClient.getAuthCodeUrl({
      scopes,
      redirectUri,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
      state,
      nonce
    });
    response.redirect(authUrl);
  } catch (error) {
    next(error);
  }
});

app.get('/auth/callback', async (request, response, next) => {
  if (!requireMsal(response)) return;
  const flow = request.session.entraFlow;
  if (!flow || typeof request.query.code !== 'string' || request.query.state !== flow.state) {
    return response.status(400).send('Respuesta de autenticación inválida o expirada.');
  }

  try {
    const token = await msalClient.acquireTokenByCode({
      code: request.query.code,
      scopes,
      redirectUri,
      codeVerifier: flow.verifier
    });
    if (token.idTokenClaims?.nonce !== flow.nonce) {
      return response.status(400).send('La respuesta de autenticación no pudo validarse.');
    }

    request.session.regenerate(error => {
      if (error) return next(error);
      request.session.user = {
        name: token.account?.name || token.idTokenClaims?.name || token.account?.username,
        username: token.account?.username || token.idTokenClaims?.preferred_username,
        provider: 'ENTRA'
      };
      request.session.save(saveError => saveError ? next(saveError) : response.redirect('/'));
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/me', (request, response) => {
  if (!request.session.user) {
    return response.status(401).json({ authenticated: false });
  }
  response.json({ authenticated: true, ...request.session.user });
});

app.post('/auth/logout', (request, response, next) => {
  request.session.destroy(error => {
    if (error) return next(error);
    response.clearCookie('mfa.sid');
    response.status(204).end();
  });
});

app.use((error, _request, response, _next) => {
  console.error(`[auth] Request failed: ${error.message}`);
  response.status(502).json({ message: 'No se pudo completar la autenticación.' });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Frontend listening at http://localhost:${port}`);
  if (!msalClient) console.warn('Microsoft Entra authentication is not configured.');
  if (!process.env.SESSION_SECRET) console.warn('SESSION_SECRET is not configured; sessions reset on restart.');
});

function escapeXml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

async function authenticateLdap(user, password) {
  const envelope = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:mfa="http://mfa.aldolares.github.com/">
  <soapenv:Header/>
  <soapenv:Body>
    <mfa:authenticate>
      <user>${escapeXml(user)}</user>
      <password>${escapeXml(password)}</password>
    </mfa:authenticate>
  </soapenv:Body>
</soapenv:Envelope>`;

  const result = await fetch(soapUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      SOAPAction: '""'
    },
    body: envelope
  });
  const responseBody = await result.text();
  if (!result.ok) {
    const fault = responseBody.match(/<(?:\w+:)?faultstring[^>]*>([^<]+)/i)?.[1] || 'no SOAP fault detail';
    console.error(`[auth] SOAP failed for user ${user.slice(0, 2)}***: HTTP ${result.status}; fault=${fault}`);
    throw new Error(`Authentication service returned HTTP ${result.status}`);
  }

  const authenticated = valueFromSoap(responseBody, ['authenticated', 'isAuthenticated'])?.toLowerCase() === 'true';
  const provider = valueFromSoap(responseBody, ['provider']) || 'UNKNOWN';
  const tags = [...responseBody.matchAll(/<([^!?/][^>]*)>/g)].map(match => match[1].split(/\s+/)[0]).join(',');
  console.info(`[auth] SOAP response elements: ${tags || 'none'}`);
  console.info(`[auth] SOAP response for user ${user.slice(0, 2)}***: authenticated=${authenticated}; provider=${provider}`);
  return { authenticated, provider };
}

function valueFromSoap(xml, names) {
  for (const name of names) {
    const match = xml.match(new RegExp(`<[^:>]+:${name}[^>]*>\\s*([^<]+?)\\s*</[^:>]+:${name}>|<${name}[^>]*>\\s*([^<]+?)\\s*</${name}>`, 'i'));
    if (match) return (match[1] || match[2]).trim();
  }
  return null;
}
