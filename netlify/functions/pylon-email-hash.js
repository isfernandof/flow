const crypto = require('crypto');

exports.handler = async (event) => {
  const secretHex = process.env.PYLON_IDENTITY_SECRET;
  const { email } = event.queryStringParameters || {};
  if (!secretHex || !email) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing secret or email' }) };
  }

  const secret = Buffer.from(secretHex, 'hex');
  const normalizedEmail = email.toLowerCase();
  const emailHash = crypto.createHmac('sha256', secret)
    .update(normalizedEmail)
    .digest('hex');

  // Identify the origin that made the request
  const requestOrigin = event.headers.origin || '';
  const allowedOrigins = [
    'https://wallet.flow.com', // production
    'https://core.flow.com', // production
    'https://flow25.webflow.io'    // staging
  ];
  // If the request origin is allowed, echo it back; otherwise default to the first allowed origin
  const corsOrigin = allowedOrigins.includes(requestOrigin)
    ? requestOrigin
    : allowedOrigins[0];

  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      // The “Vary: Origin” header tells caches that responses differ by Origin [oai_citation:1‡developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin#:~:text=Limiting%20the%20possible%20%60Access,value%20as%20the%20Origin%20value).
      'Vary': 'Origin'
    },
    body: JSON.stringify({ email: normalizedEmail, email_hash: emailHash })
  };
};
