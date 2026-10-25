
export async function onRequestPost({ request, env }) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store"
  };

  const reply = (status, body) =>
    new Response(JSON.stringify(body), { status, headers });

  try {
    const origin = request.headers.get("Origin");

    if (origin && origin !== "https://kkpfranchise.com") {
      return reply(403, { error: "Origin not allowed." });
    }

    const body = await request.json();

    const {
      name,
      email,
      phone,
      location,
      message,
      turnstileToken
    } = body;

    if (
      !name || !email || !phone ||
      !location || !turnstileToken
    ) {
      return reply(400, { error: "Missing required fields." });
    }

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof phone !== "string" ||
      typeof location !== "string" ||
      typeof message !== "string" ||
      typeof turnstileToken !== "string" ||
      name.length > 150 ||
      email.length > 254 ||
      phone.length > 40 ||
      location.length > 180 ||
      message.length > 3000
    ) {
      return reply(400, { error: "Invalid application fields." });
    }

    if (!env.TURNSTILE_SECRET_KEY ||
        !env.SUPABASE_URL ||
        !env.SUPABASE_SERVICE_ROLE_KEY) {
      return reply(503, { error: "Service not configured." });
    }

    const verifyBody = new FormData();
    verifyBody.append("secret", env.TURNSTILE_SECRET_KEY);
    verifyBody.append("response", turnstileToken);

    const verification = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { method: "POST", body: verifyBody }
    );

    if (!verification.ok) {
      return reply(503, { error: "Verification unavailable." });
    }

    const result = await verification.json();

    if (
      !result.success ||
      result.hostname !== "kkpfranchise.com"
    ) {
      return reply(403, { error: "Security verification failed." });
    }

    const supabaseResponse = await fetch(
      `${env.SUPABASE_URL.replace(/\/$/, "")}/rest/v1/rpc/submit_franchise_application`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`
        },
        body: JSON.stringify({
          p_applicant_name: name,
          p_email: email,
          p_phone: phone,
          p_preferred_location: location,
          p_message: message
        })
      }
    );

    if (!supabaseResponse.ok) {
      return reply(400, {
        error: "Unable to submit application. Please check your details or try again later."
      });
    }

    return reply(200, {
      success: true,
      message: "Application submitted successfully."
    });

  } catch {
    return reply(500, {
      error: "An unexpected error occurred."
    });
  }
}

export async function onRequest() {
  return new Response(
    JSON.stringify({ error: "Method not allowed." }),
    {
      status: 405,
      headers: { "Content-Type": "application/json" }
    }
  );
}
