const crypto = require('crypto');

function base64URLEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export default function handler(req, res) {
  // Generate PKCE code verifier + challenge
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(
    crypto.createHash('sha256').update(codeVerifier).digest()
  );
  const state = base64URLEncode(crypto.randomBytes(16));

  // Store verifier + state in cookies so /callback can verify
  res.setHeader('Set-Cookie', [
    `kick_code_verifier=${codeVerifier}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
    `kick_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  ]);

  const scopes = [
    'user:read',
    'channel:read',
    'events:subscribe'
  ].join(' ');

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.KICK_CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI,
    scope: scopes,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state
  });

  res.redirect(`https://id.kick.com/oauth/authorize?${params.toString()}`);
}
