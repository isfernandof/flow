// netlify/functions/pylon-email-hash.js
const crypto = require('crypto');

exports.handler = async (event) => {
  // Pull the secret (as hex) from an environment variable
  const secretHex = process.env.PYLON_IDENTITY_SECRET;
  if (!secretHex) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Secret not configured.' }) };
  }

  // Read the email from query string, normalize case
  const { email } = event.queryStringParameters || {};
  if (!email) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing email.' }) };
  }
  const normalizedEmail = email.toLowerCase();

  // Convert the hex secret into bytes and compute HMAC
  const secret = Buffer.from(secretHex, 'hex');
  const emailHash = crypto.createHmac('sha256', secret)
                          .update(normalizedEmail)
                          .digest('hex');

  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      // Allow your Webflow site to call this function (adjust to your domain)
      'Access-Control-Allow-Origin': 'https://wallet.flow.com'
    },
    body: JSON.stringify({ email: normalizedEmail, email_hash: emailHash })
  };
};
