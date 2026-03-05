export default async function handler(req, res) {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send('Missing code or state. Please try again.');
  }

  // Extract verifier from state: format is nonce.base64url(verifier)
  const dotIndex = state.indexOf('.');
  if (dotIndex === -1) {
    return res.status(400).send('Invalid state format. Please try again.');
  }

  const verifierEncoded = state.slice(dotIndex + 1);
  let codeVerifier;
  try {
    // Restore base64url padding and decode
    const padded = verifierEncoded.replace(/-/g, '+').replace(/_/g, '/');
    const pad = padded.length % 4;
    const paddedFull = pad ? padded + '='.repeat(4 - pad) : padded;
    codeVerifier = Buffer.from(paddedFull, 'base64').toString('utf8');
  } catch (err) {
    return res.status(400).send('Could not decode verifier. Please try again.');
  }

  if (!codeVerifier) {
    return res.status(400).send('Missing code verifier. Please try again.');
  }

  try {
    const tokenRes = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: process.env.KICK_CLIENT_ID,
        client_secret: process.env.KICK_CLIENT_SECRET,
        redirect_uri: process.env.REDIRECT_URI,
        code_verifier: codeVerifier,
        code
      }).toString()
    });

    const data = await tokenRes.json();

    if (!tokenRes.ok || !data.access_token) {
      console.error('Token exchange failed:', JSON.stringify(data));
      return res.status(500).send('Token exchange failed: ' + (data.message || data.error || 'unknown error'));
    }

    // Store token in secure HttpOnly cookie
    res.setHeader('Set-Cookie',
      `kick_access_token=${data.access_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${data.expires_in || 3600}`
    );

    res.redirect('/?connected=true');

  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).send('Something went wrong: ' + err.message);
  }
}
