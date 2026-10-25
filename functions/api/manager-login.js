
const ORIGIN = 'https://kkpfranchise.com';

const response = (payload, status = 200) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    }
  });

const denied = () =>
  response({ error: 'Invalid credentials or manager access unavailable' }, 401);

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get('Origin');
  if (origin !== ORIGIN) {
    return response({ error: 'Forbidden' }, 403);
  }

  if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY ||
      !env.SUPABASE_SERVICE_ROLE_KEY) {
    return response({ error: 'Manager login is not configured' }, 503);
  }

  const base = env.SUPABASE_URL.replace(/\/$/, '');
  let input;

  try {
    if (Number(request.headers.get('content-length') || 0) > 4096) {
      return response({ error: 'Invalid request' }, 400);
    }
    input = await request.json();
  } catch {
    return response({ error: 'Invalid request' }, 400);
  }

  const username = typeof input?.username === 'string'
    ? input.username.trim().toLowerCase() : '';
  const password = typeof input?.password === 'string'
    ? input.password : '';

  if (!/^[a-z][a-z0-9_]{3,19}$/.test(username) ||
      !password || password.length > 1024) {
    return denied();
  }

  try {
    const lookup = await fetch(
      `${base}/rest/v1/rpc/kkp_manager_login_lookup`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ p_username: username })
      }
    );

    if (!lookup.ok) {
      return response({ error: 'Manager login service unavailable' }, 503);
    }

    const profiles = await lookup.json();
    const profile = Array.isArray(profiles) ? profiles[0] : null;

    if (!profile?.email || !profile?.user_id) return denied();

    const auth = await fetch(
      `${base}/auth/v1/token?grant_type=password`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_ANON_KEY,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: profile.email,
          password
        })
      }
    );

    if (!auth.ok) return denied();

    const session = await auth.json();

    if (!session?.access_token ||
        !session?.refresh_token ||
        session.user?.id !== profile.user_id) {
      return denied();
    }

    if (profile.approval_status !== 'approved') return denied();

    return response({
      access_token: session.access_token,
      refresh_token: session.refresh_token
    });
  } catch {
    return response({ error: 'Manager login service unavailable' }, 503);
  }
}
