
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
      turnstileToken,
      referralCode
    } = body;

    if (!name || !email || !phone || !location || !turnstileToken) {
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
      message.length > 3000 ||
      (referralCode != null &&
        (typeof referralCode !== "string" ||
          !/^KKP-[A-F0-9]{16}$/.test(referralCode)))
    ) {
      return reply(400, { error: "Invalid application fields." });
    }

    if (
      !env.TURNSTILE_SECRET_KEY ||
      !env.SUPABASE_URL ||
      !env.SUPABASE_SERVICE_ROLE_KEY
    ) {
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

    const verificationResult = await verification.json();

    if (
      !verificationResult.success ||
      verificationResult.hostname !== "kkpfranchise.com"
    ) {
      return reply(403, { error: "Security verification failed." });
    }

    const hasReferral = referralCode != null && referralCode !== "";

    const rpcName = hasReferral
      ? "submit_franchise_manager_application"
      : "submit_franchise_application";

    const rpcBody = {
      p_applicant_name: name,
      p_email: email,
      p_phone: phone,
      p_preferred_location: location,
      p_message: message
    };

    if (hasReferral) {
      rpcBody.p_referral_code = referralCode;
    }

    const supabaseUrl = env.SUPABASE_URL.replace(/\/$/, "");

    const authHeaders = {
      "Content-Type": "application/json",
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`
    };

    const supabaseResponse = await fetch(
      `${supabaseUrl}/rest/v1/rpc/${rpcName}`,
      {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify(rpcBody)
      }
    );

    if (!supabaseResponse.ok) {
      return reply(400, {
        error: hasReferral
          ? "Unable to submit application. Please check your referral link and application details."
          : "Unable to submit application. Please check your details or try again later."
      });
    }

    const applicationId = await supabaseResponse.json();

    let referenceNumber = null;

    try {
      const referenceResponse = await fetch(
        `${supabaseUrl}/rest/v1/rpc/get_franchise_reference`,
        {
          method: "POST",
          headers: authHeaders,
          body: JSON.stringify({
            p_application_id: applicationId
          })
        }
      );

      if (referenceResponse.ok) {
        referenceNumber = await referenceResponse.json();
      }
    } catch {
      // Application was already saved.
      // Do not treat reference lookup failure as submission failure.
    }

    return reply(200, {
      success: true,
      applicationId,
      referenceNumber,
      applicationType: hasReferral ? "manager_referral" : "direct",
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
