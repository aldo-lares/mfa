const assert = require('node:assert/strict');
const { after, before, test } = require('node:test');

process.env.SESSION_SECRET = 'test-session-secret-with-at-least-32-characters';
delete process.env.KEYCLOAK_ISSUER;
delete process.env.KEYCLOAK_CLIENT_ID;
delete process.env.KEYCLOAK_CLIENT_SECRET;
delete process.env.ENTRA_EXTERNAL_AUTHORITY;
delete process.env.ENTRA_EXTERNAL_CLIENT_ID;
delete process.env.ENTRA_EXTERNAL_CLIENT_SECRET;

const { app, createEntraLogoutUrl, hasEntraMfaEvidence, hasMfaEvidence, validateAuthority } = require('../server');

let baseUrl;
let server;

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
});

test('legacy Entra login routes to the workforce provider', async () => {
  const response = await fetch(`${baseUrl}/auth/entra/login`, { redirect: 'manual' });

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), '/auth/workforce/login');
});

test('legacy callback preserves query parameters', async () => {
  const response = await fetch(`${baseUrl}/auth/callback?code=abc&state=def`, { redirect: 'manual' });

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), '/auth/workforce/callback?code=abc&state=def');
});

test('an unconfigured customer provider fails closed', async () => {
  const response = await fetch(`${baseUrl}/auth/customer/login`);

  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { message: 'La autenticación customer no está configurada.' });
});

test('External ID authority accepts only the ciamlogin tenant root', () => {
  assert.equal(validateAuthority('https://contoso.ciamlogin.com/'), null);
  assert.match(
    validateAuthority('https://contoso.ciamlogin.com/tenant-id'),
    /root ciamlogin\.com tenant URL/
  );
});

test('direct LDAP authentication is blocked to prevent bypassing MFA', async () => {
  const response = await fetch(`${baseUrl}/api/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'alice', password: 'password' })
  });

  assert.equal(response.status, 410);
  assert.match((await response.json()).message, /LDAP directo fue deshabilitado/);
});

test('a customer callback without a matching flow is rejected', async () => {
  const response = await fetch(`${baseUrl}/auth/customer/callback?code=abc&state=def`);

  assert.equal(response.status, 400);
  assert.match(await response.text(), /inválida o expirada/);
});

test('MFA evidence accepts OTP AMR or the signed realm policy claim', () => {
  assert.equal(hasMfaEvidence({ amr: ['pwd', 'otp'] }), true);
  assert.equal(hasMfaEvidence({ mfa: true }), true);
  assert.equal(hasMfaEvidence({ amr: ['pwd'] }), false);
  assert.equal(hasMfaEvidence({ mfa: 'true' }), false);
});

test('an unconfigured External ID provider fails closed', async () => {
  const response = await fetch(`${baseUrl}/auth/external/login`);

  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { message: 'La autenticación external no está configurada.' });
});

test('External ID records signed MFA or OTP authentication methods when emitted', () => {
  assert.equal(hasEntraMfaEvidence({ amr: ['pwd', 'mfa'] }), true);
  assert.equal(hasEntraMfaEvidence({ amr: ['pwd', 'otp'] }), true);
  assert.equal(hasEntraMfaEvidence({ amr: ['pwd'] }), false);
});

test('Entra logout uses the issuer tenant and an exact registered return URI', () => {
  const url = createEntraLogoutUrl(
    'https://contoso.ciamlogin.com/tenant-id/v2.0',
    'https://app.example.com/'
  );

  assert.equal(url.origin, 'https://contoso.ciamlogin.com');
  assert.equal(url.pathname, '/tenant-id/oauth2/v2.0/logout');
  assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'https://app.example.com/');
});