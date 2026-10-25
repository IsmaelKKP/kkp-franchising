// Cloudflare Pages Function. Set ADMIN_LOGIN_USERNAME and ADMIN_LOGIN_EMAIL
// as environment variables in Cloudflare Pages (Production and Preview).
// The email mapping remains server-side; no service-role key is required.
export async function onRequestPost({ request, env }) {
  const json = (payload, status = 200) => new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
  if (!env.ADMIN_LOGIN_USERNAME || !env.ADMIN_LOGIN_EMAIL || !env.SUPABASE_URL || !env.SUPABASE_ANON_KEY) {
    return json({ error: 'Login service is not configured' }, 503);
  }
  let input;
  try {
    if (Number(request.headers.get('content-length') || 0) > 4096) return json({ error: 'Invalid request' }, 400);
    input = await request.json();
  } catch { return json({ error: 'Invalid request' }, 400); }
  const username = typeof input?.username === 'string' ? input.username.trim() : '';
  const password = typeof input?.password === 'string' ? input.password : '';
  if (!username || !password || password.length > 1024) return json({ error: 'Invalid credentials' }, 401);
  // Do not disclose whether the username exists.
  if (username !== env.ADMIN_LOGIN_USERNAME) return json({ error: 'Invalid credentials' }, 401);
  try {
    const url = `${env.SUPABASE_URL.replace(/\/$/, '')}/auth/v1/token?grant_type=password`;
    const result = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': env.SUPABASE_ANON_KEY },
      body: JSON.stringify({ email: env.ADMIN_LOGIN_EMAIL, password })
    });
    if (!result.ok) return json({ error: 'Invalid credentials' }, 401);
    const session = await result.json();
    if (!session.access_token || !session.refresh_token) return json({ error: 'Authentication failed' }, 502);
    return json({ access_token: session.access_token, refresh_token: session.refresh_token });
  } catch { return json({ error: 'Authentication service unavailable' }, 503); }
}
