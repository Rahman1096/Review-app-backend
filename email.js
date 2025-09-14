const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail", // You can change to your provider
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function baseTemplate({
  title,
  preheader,
  heading,
  bodyHtml,
  ctaUrl,
  ctaLabel,
  footerNote,
}) {
  const brand = "devC";
  const year = new Date().getFullYear();
  const safePreheader = preheader || "";
  return {
    subject: `${brand} — ${title}`,
    html: `<!doctype html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${brand}</title>
    <style>
      body { background:#f6f9fc; margin:0; padding:0; -webkit-font-smoothing:antialiased; }
      .container { max-width:560px; margin:24px auto; background:#ffffff; border-radius:12px; box-shadow:0 2px 10px rgba(0,0,0,0.06); overflow:hidden; }
      .header { padding:20px 24px; background:#0d6efd; color:#fff; font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
      .brand { font-size:18px; font-weight:600; }
      .content { padding:24px; font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#1f2937; line-height:1.6; }
      h1 { font-size:20px; margin:0 0 12px; color:#111827; }
      p { margin:0 0 12px; }
      .btn { display:inline-block; padding:12px 18px; background:#0d6efd; color:#fff !important; text-decoration:none; border-radius:8px; font-weight:600; }
      .muted { color:#6b7280; font-size:12px; }
      .footer { padding:16px 24px; color:#6b7280; font-size:12px; font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
      .link { word-break:break-all; color:#0d6efd; }
    </style>
  </head>
  <body>
    <span style="display:none; visibility:hidden; opacity:0; height:0; width:0; overflow:hidden">${safePreheader}</span>
    <div class="container">
      <div class="header"><div class="brand">${brand}</div></div>
      <div class="content">
        <h1>${heading}</h1>
        ${bodyHtml}
        ${
          ctaUrl
            ? `<p style="margin:20px 0 8px"><a class="btn" href="${ctaUrl}" target="_blank" rel="noopener">${
                ctaLabel || "Open"
              }</a></p>`
            : ""
        }
        ${
          ctaUrl
            ? `<p class="muted">If the button doesn’t work, copy and paste this link into your browser:<br /><a class="link" href="${ctaUrl}" target="_blank" rel="noopener">${ctaUrl}</a></p>`
            : ""
        }
        ${
          footerNote
            ? `<p class="muted" style="margin-top:16px">${footerNote}</p>`
            : ""
        }
      </div>
      <div class="footer">© ${year} ${brand}. All rights reserved.</div>
    </div>
  </body>
</html>`,
  };
}

function sendVerificationEmail(to, token, username, baseUrl) {
  const frontend = baseUrl || process.env.FRONTEND_URL;
  const url = `${frontend}/verify-email?token=${token}`;
  try {
    console.log(
      `[mail] verification link for ${to} (${username || "?"}):`,
      url
    );
  } catch {}
  const tpl = baseTemplate({
    title: "Verify your email",
    preheader: "Confirm your email to activate your account",
    heading: "Verify your email",
    bodyHtml: `<p>Hi ${
      username || "there"
    },</p><p>Thanks for signing up for devC. Please confirm your email address to activate your account and start posting reviews.</p>`,
    ctaUrl: url,
    ctaLabel: "Verify email",
    footerNote:
      "If you didn’t create an account, you can safely ignore this email.",
  });
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: tpl.subject,
    html: tpl.html,
    text: `Verify your email\n\nHi ${
      username || "there"
    },\nThanks for signing up for devC. Confirm your email to activate your account.\n\nVerification link: ${url}\n\nIf you didn’t create an account, ignore this email.`,
  });
}

function sendPasswordResetEmail(to, token, username, baseUrl) {
  const frontend = baseUrl || process.env.FRONTEND_URL;
  const url = `${frontend}/reset-password?token=${token}`;
  try {
    console.log(`[mail] reset link for ${to} (${username || "?"}):`, url);
  } catch {}
  const tpl = baseTemplate({
    title: "Reset your password",
    preheader: "Use the secure link below to reset your password",
    heading: "Reset your password",
    bodyHtml: `<p>Hi ${
      username || "there"
    },</p><p>We received a request to reset your password for your devC account. Click the button below to set a new one.</p><p class="muted">This link will expire in 30 minutes for your security.</p>`,
    ctaUrl: url,
    ctaLabel: "Reset password",
    footerNote: "Didn’t request this? You can safely ignore this email.",
  });
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: tpl.subject,
    html: tpl.html,
    text: `Reset your password\n\nHi ${
      username || "there"
    },\nWe received a request to reset your password for your devC account. Use the link below to set a new one.\n\nReset link (expires in 30 minutes): ${url}\n\nIf you didn’t request this, you can ignore this email.`,
  });
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail };
