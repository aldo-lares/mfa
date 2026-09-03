const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const port = Number(process.env.PORT || 3000);
const soapUrl = process.env.SOAP_URL || 'http://localhost:8080/auth';
const index = fs.readFileSync(path.join(__dirname, 'index.html'));

function escapeXml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function send(response, status, body, contentType = 'application/json; charset=utf-8') {
  response.writeHead(status, { 'Content-Type': contentType });
  response.end(body);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', chunk => {
      body += chunk;
      if (body.length > 10_000) {
        request.destroy();
        reject(new Error('Request body too large'));
      }
    });
    request.on('end', () => resolve(body));
    request.on('error', reject);
  });
}

async function authenticate(user, password) {
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

const server = http.createServer(async (request, response) => {
  try {
    if (request.method === 'GET' && request.url === '/') {
      return send(response, 200, index, 'text/html; charset=utf-8');
    }

    if (request.method === 'POST' && request.url === '/api/authenticate') {
      const payload = JSON.parse(await readBody(request));
      const user = typeof payload.user === 'string' ? payload.user.trim() : '';
      const password = typeof payload.password === 'string' ? payload.password : '';
      if (!user || !password) {
        return send(response, 400, JSON.stringify({ message: 'Usuario y contraseña son obligatorios.' }));
      }

      console.info(`[auth] Login request received for user ${user.slice(0, 2)}***`);
      const result = await authenticate(user, password);
      return send(response, 200, JSON.stringify({ ...result, user }));
    }

    send(response, 404, JSON.stringify({ message: 'Not found' }));
  } catch (error) {
    console.error(`[auth] Login request failed: ${error.message}`);
    send(response, 502, JSON.stringify({ message: 'No se pudo contactar con el servicio de autenticación.' }));
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`Frontend listening at http://localhost:${port}`);
});