export default async function handler(req, res) {
  const { code, state } = req.query;

  // Debug: show exactly what we received
  if (!code && !state) {
    return res.status(400).send('No code or state received. Query params: ' + JSON.stringify(req.query));
  }

  if (!code) {
    return res.status(400).send('No code received. State was: ' + state);
  }

  if (!state) {
    return res.status(400).send('No state received. Code was present.');
  }

  // Extract verifier from state
  const dotIndex = state.indexOf('.');
  if (dotIndex === -1) {
    return res.status(400).send('State has no dot separator. State received: ' + state.substring(0, 20) + '...');
  }

  const verifierEncoded = state.slice(dotIndex + 1);

  let codeVerifier;
  try {
    const padded = verifierEncoded.replace(/-/g, '+').replace(/_/g, '/');
    const pad = padded.length % 4;
    const paddedFull = pad ? padded + '='.repeat(4 - pad) : padded;
    codeVerifier = Buffer.from(paddedFull, 'base64').toString('utf8');
  } catch (err) {
    return res.status(400).send('Decode error: ' + err.message + ' | encoded was: ' + verifierEncoded.substring(0, 20));
  }

  if (!codeVerifier) {
    return res.status(400).send('codeVerifier empty after decode.');
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
      return res.status(500).send('Token exchange failed: ' + JSON.stringify(data));
    }

    res.setHeader('Set-Cookie',
      `kick_access_token=${data.access_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${data.expires_in || 3600}`
    );

    res.redirect('/?connected=true');

  } catch (err) {
    res.status(500).send('Fetch error: ' + err.message);
  }
}
