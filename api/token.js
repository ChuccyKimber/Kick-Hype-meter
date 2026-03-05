export default function handler(req, res) {
  const cookies = Object.fromEntries(
    (req.headers.cookie || '').split(';').map(c => {
      const [k, ...v] = c.trim().split('=');
      return [k, v.join('=')];
    })
  );

  const token = cookies['kick_access_token'];

  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  res.status(200).json({ access_token: token });
}
