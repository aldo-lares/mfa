const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const port = Number(process.env.PORT || 3000);
const soapUrl = process.env.SOAP_URL || 'http://localhost:8080/auth';
const index = fs.readFileSync(path.join(__dirname, 'index.html'));
const crypto = require('node:crypto');
const session = require('express-session');
const { ConfidentialClientApplication, CryptoProvider } = require('@azure/msal-node');

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const scopes = ['openid', 'profile', 'email'];
const cryptoProvider = new CryptoProvider();

const customerProvider = {
  issuer: process.env.KEYCLOAK_ISSUER,
  internalOrigin: process.env.KEYCLOAK_INTERNAL_ORIGIN,
  clientId: process.env.KEYCLOAK_CLIENT_ID,
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET,
  redirectUri: process.env.KEYCLOAK_REDIRECT_URI || `http://localhost:${port}/auth/customer/callback`,
  postLogoutRedirectUri: process.env.KEYCLOAK_POST_LOGOUT_REDIRECT_URI || `http://localhost:${port}/`
};
let customerOidc;

const authProviders = new Map([
  createAuthProvider('workforce', {
    tenantId: process.env.ENTRA_WORKFORCE_TENANT_ID || process.env.ENTRA_TENANT_ID,
    clientId: process.env.ENTRA_WORKFORCE_CLIENT_ID || process.env.ENTRA_CLIENT_ID,
    clientSecret: process.env.ENTRA_WORKFORCE_CLIENT_SECRET || process.env.ENTRA_CLIENT_SECRET,
    authority: process.env.ENTRA_WORKFORCE_AUTHORITY,
    redirectUri: process.env.ENTRA_WORKFORCE_REDIRECT_URI || process.env.ENTRA_REDIRECT_URI || `http://localhost:${port}/auth/workforce/callback`
  })
]);

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

function createAuthProvider(name, config) {
  const authority = config.authority || (config.tenantId ? `https://login.microsoftonline.com/${config.tenantId}` : null);
  const configurationError = validateAuthority(authority);
  const complete = config.clientId && config.clientSecret && authority && !configurationError;
  const knownAuthorities = authority && new URL(authority).hostname.endsWith('.ciamlogin.com')
    ? [new URL(authority).hostname]
    : undefined;
  const client = complete
    ? new ConfidentialClientApplication({
        auth: {
          clientId: config.clientId,
          authority,
          clientSecret: config.clientSecret,
          ...(knownAuthorities ? { knownAuthorities } : {})
        }
      })
    : null;

  return [name, { ...config, authority, client, configurationError }];
}

function validateAuthority(authority) {
  if (!authority) return null;
  let parsed;
  try {
    parsed = new URL(authority);
  } catch {
    return 'Authority must be a valid URL.';
  }
  if (parsed.protocol !== 'https:') return 'Authority must use HTTPS.';
  if (parsed.hostname.endsWith('.ciamlogin.com') && parsed.pathname !== '/') {
    return 'External ID authority must use the root ciamlogin.com tenant URL.';
  }
  return null;
}

function requireAuthProvider(providerName, response) {
  const provider = authProviders.get(providerName);
  if (provider?.client) return provider;
  response.status(503).json({ message: `La autenticación ${providerName} no está configurada.` });
  return null;
}

async function getCustomerOidc() {
  if (!customerProvider.issuer || !customerProvider.clientId || !customerProvider.clientSecret) return null;
  if (customerOidc) return customerOidc;

  const oidc = await import('openid-client');
  const issuer = new URL(customerProvider.issuer);
  if (process.env.NODE_ENV === 'production' && issuer.protocol !== 'https:') {
    throw new Error('Keycloak issuer must use HTTPS in production.');
  }
  const options = {};
  if (issuer.protocol === 'http:') options.execute = [oidc.allowInsecureRequests];
  if (customerProvider.internalOrigin) {
    options[oidc.customFetch] = (input, init) => {
      const target = new URL(input instanceof Request ? input.url : input);
      if (target.origin === issuer.origin) {
        const internal = new URL(customerProvider.internalOrigin);
        target.protocol = internal.protocol;
        target.host = internal.host;
      }
      return fetch(target, init);
    };
  }
  const config = await oidc.discovery(
    new URL(customerProvider.issuer),
    customerProvider.clientId,
    customerProvider.clientSecret,
    undefined,
    options
  );
  customerOidc = { oidc, config };
  return customerOidc;
}

function hasMfaEvidence(claims) {
  const methods = Array.isArray(claims?.amr) ? claims.amr : [];
  return methods.includes('otp') || claims?.mfa === true;
}

app.get('/', (_request, response) => {
  response.type('html').send(index);
});

app.post('/api/authenticate', async (request, response, next) => {
  response.status(410).json({ message: 'El acceso LDAP directo fue deshabilitado; usa el inicio de sesión con MFA.' });
});

app.get('/auth/entra/login', (_request, response) => {
  response.redirect('/auth/workforce/login');
});

app.get('/auth/callback', (request, response) => {
  const query = new URLSearchParams(request.query).toString();
  response.redirect(`/auth/workforce/callback${query ? `?${query}` : ''}`);
});

app.get('/auth/customer/login', async (request, response, next) => {
  try {
    const client = await getCustomerOidc();
    if (!client) return response.status(503).json({ message: 'La autenticación customer no está configurada.' });

    const verifier = client.oidc.randomPKCECodeVerifier();
    const challenge = await client.oidc.calculatePKCECodeChallenge(verifier);
    const state = client.oidc.randomState();
    const nonce = client.oidc.randomNonce();
    request.session.oidcFlow = { verifier, state, nonce };

    const authUrl = client.oidc.buildAuthorizationUrl(client.config, {
      redirect_uri: customerProvider.redirectUri,
      scope: scopes.join(' '),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
      nonce,
      ui_locales: 'es'
    });
    response.redirect(authUrl.href);
  } catch (error) {
    next(error);
  }
});

app.get('/auth/customer/callback', async (request, response, next) => {
  const flow = request.session.oidcFlow;
  if (!flow || typeof request.query.code !== 'string' || request.query.state !== flow.state) {
    return response.status(400).send('Respuesta de autenticación inválida o expirada.');
  }

  try {
    const client = await getCustomerOidc();
    if (!client) return response.status(503).json({ message: 'La autenticación customer no está configurada.' });
    const callbackUrl = new URL(customerProvider.redirectUri);
    callbackUrl.search = new URL(request.originalUrl, customerProvider.redirectUri).search;
    const tokens = await client.oidc.authorizationCodeGrant(client.config, callbackUrl, {
      pkceCodeVerifier: flow.verifier,
      expectedState: flow.state,
      expectedNonce: flow.nonce
    });
    const claims = tokens.claims();
    if (!claims?.iss || !claims?.sub || !hasMfaEvidence(claims)) {
      return response.status(403).send('La identidad no contiene evidencia válida de MFA.');
    }

    request.session.regenerate(error => {
      if (error) return next(error);
      request.session.user = {
        name: claims.name || claims.preferred_username,
        username: claims.preferred_username,
        provider: 'KEYCLOAK_LDAP',
        issuer: claims.iss,
        subject: claims.sub,
        authTime: claims.auth_time,
        mfa: true
      };
      request.session.oidcIdToken = tokens.id_token;
      request.session.save(saveError => saveError ? next(saveError) : response.redirect('/'));
    });
  } catch (error) {
    next(error);
  }
});

app.get('/auth/:provider/login', async (request, response, next) => {
  const provider = requireAuthProvider(request.params.provider, response);
  if (!provider) return;
  try {
    const { verifier, challenge } = await cryptoProvider.generatePkceCodes();
    const state = crypto.randomBytes(32).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    request.session.entraFlow = { verifier, state, nonce, provider: request.params.provider };

    const authUrl = await provider.client.getAuthCodeUrl({
      scopes,
      redirectUri: provider.redirectUri,
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

app.get('/auth/:provider/callback', async (request, response, next) => {
  const providerName = request.params.provider;
  const provider = requireAuthProvider(providerName, response);
  if (!provider) return;
  const flow = request.session.entraFlow;
  if (!flow || flow.provider !== providerName || typeof request.query.code !== 'string' || request.query.state !== flow.state) {
    return response.status(400).send('Respuesta de autenticación inválida o expirada.');
  }

  try {
    const token = await provider.client.acquireTokenByCode({
      code: request.query.code,
      scopes,
      redirectUri: provider.redirectUri,
      codeVerifier: flow.verifier
    });
    if (token.idTokenClaims?.nonce !== flow.nonce) {
      return response.status(400).send('La respuesta de autenticación no pudo validarse.');
    }
    if (!token.idTokenClaims?.iss || !token.idTokenClaims?.sub) {
      return response.status(400).send('La identidad autenticada no contiene identificadores estables.');
    }

    request.session.regenerate(error => {
      if (error) return next(error);
      request.session.user = {
        name: token.account?.name || token.idTokenClaims?.name || token.account?.username,
        username: token.account?.username || token.idTokenClaims?.preferred_username,
        provider: providerName.toUpperCase(),
        issuer: token.idTokenClaims?.iss,
        subject: token.idTokenClaims?.sub,
        tenant: token.idTokenClaims?.tid
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
  const idToken = request.session.oidcIdToken;
  request.session.destroy(error => {
    if (error) return next(error);
    response.clearCookie('mfa.sid');
    if (!idToken || !customerOidc) return response.redirect(303, '/');
    const endpoint = customerOidc.config.serverMetadata().end_session_endpoint;
    if (!endpoint) return response.redirect(303, '/');
    const logoutUrl = new URL(endpoint);
    logoutUrl.searchParams.set('id_token_hint', idToken);
    logoutUrl.searchParams.set('post_logout_redirect_uri', customerProvider.postLogoutRedirectUri);
    response.redirect(303, logoutUrl.href);
  });
});

app.use((error, _request, response, _next) => {
  console.error(`[auth] Request failed: ${error.message}`);
  response.status(502).json({ message: 'No se pudo completar la autenticación.' });
});

if (require.main === module) {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Frontend listening at http://localhost:${port}`);
    for (const [name, provider] of authProviders) {
      if (provider.configurationError) console.warn(`Microsoft Entra ${name} configuration is invalid: ${provider.configurationError}`);
      else if (!provider.client) console.warn(`Microsoft Entra ${name} authentication is not configured.`);
    }
    if (!customerProvider.issuer || !customerProvider.clientId || !customerProvider.clientSecret) console.warn('Keycloak customer authentication is not configured.');
    if (!process.env.SESSION_SECRET) console.warn('SESSION_SECRET is not configured; sessions reset on restart.');
  });
}

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

module.exports = { app, authProviders, hasMfaEvidence, validateAuthority };
