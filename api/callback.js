export default async function handler(req, res) {
  const { code, state } = req.query;

  // Parse cookies
  const cookies = Object.fromEntries(
    (req.headers.cookie || '').split(';').map(c => {
      const [k, ...v] = c.trim().split('=');
      return [k, v.join('=')];
    })
  );

  const savedState = cookies['kick_state'];
  const codeVerifier = cookies['kick_code_verifier'];

  // Validate state to prevent CSRF
  if (!state || state !== savedState) {
    return res.status(400).send('Invalid state parameter. Please try again.');
  }

  if (!code || !codeVerifier) {
    return res.status(400).send('Missing code or verifier. Please try again.');
  }

  try {
    // Exchange code for token — client secret stays server-side
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
      console.error('Token exchange failed:', data);
      return res.status(500).send('Token exchange failed. Please try again.');
    }

    // Store access token in secure cookie, redirect back to app
    res.setHeader('Set-Cookie', [
      `kick_access_token=${data.access_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${data.expires_in || 3600}`,
      `kick_refresh_token=${data.refresh_token || ''}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`,
      // Clear PKCE cookies
      `kick_code_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
      `kick_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
    ]);

    // Redirect back to the app — token is in cookie, never in URL
    res.redirect('/?connected=true');

  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).send('Something went wrong. Please try again.');
  }
}
