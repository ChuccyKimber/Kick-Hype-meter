const crypto = require('crypto');

function base64URLEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export default function handler(req, res) {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(
    crypto.createHash('sha256').update(codeVerifier).digest()
  );
  const nonce = base64URLEncode(crypto.randomBytes(8));

  // Encode verifier into state so it survives the cross-site redirect
  // Format: nonce.base64url(verifier)
  const verifierEncoded = Buffer.from(codeVerifier).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const state = nonce + '.' + verifierEncoded;

  const scopes = ['user:read', 'channel:read', 'events:subscribe'].join(' ');

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
