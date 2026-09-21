// backend/src/lib/mailer.js
// Envoi d'emails transactionnels via Resend (HTTP, sans dépendance).
// Sans RESEND_API_KEY : mode dev — le lien est loggé et renvoyé à l'appelant
// (jamais en production). Ajoutez RESEND_API_KEY + FRONTEND_URL en prod.
const nodemailer = require('nodemailer')
const { NODE_ENV } = require('../config/env')

const RESEND_API_KEY = process.env.RESEND_API_KEY || null
const RESEND_FROM = process.env.RESEND_FROM || process.env.FROM_EMAIL || 'Agro Véto Services <onboarding@resend.dev>'

// Configuration SMTP (Gmail, Brevo, OVH, Hostinger, cPanel, etc.)
const SMTP_HOST = process.env.SMTP_HOST || null
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587
const SMTP_USER = process.env.SMTP_USER || process.env.GMAIL_USER || null
const SMTP_PASS = process.env.SMTP_PASS || process.env.SMTP_PASSWORD || process.env.GMAIL_APP_PASSWORD || null
const SMTP_SECURE = process.env.SMTP_SECURE === 'true' || SMTP_PORT === 465
const SMTP_FROM = process.env.SMTP_FROM || process.env.FROM_EMAIL || (SMTP_USER ? `Agro Véto Services <${SMTP_USER}>` : RESEND_FROM)

let transporter = null

function getTransporter() {
  if (transporter) return transporter
  if (SMTP_USER && SMTP_PASS) {
    if (process.env.SMTP_SERVICE === 'gmail' || (SMTP_USER && SMTP_USER.endsWith('@gmail.com') && !SMTP_HOST)) {
      transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: SMTP_USER,
          pass: SMTP_PASS,
        },
      })
    } else if (SMTP_HOST) {
      transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_SECURE,
        auth: {
          user: SMTP_USER,
          pass: SMTP_PASS,
        },
      })
    }
  }
  return transporter
}

function hasMailer() {
  return Boolean(RESEND_API_KEY || (SMTP_USER && SMTP_PASS))
}

async function sendMail({ to, subject, html }) {
  // 1. Essai via SMTP (Gmail / Pro) si configuré
  const smtp = getTransporter()
  if (smtp) {
    const info = await smtp.sendMail({
      from: SMTP_FROM,
      to,
      subject,
      html,
    })
    return { sent: true, id: info.messageId, provider: 'smtp' }
  }

  // 2. Essai via Resend si configuré
  if (RESEND_API_KEY) {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from: RESEND_FROM, to, subject, html }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      throw new Error(data?.message || `Envoi email impossible (${res.status})`)
    }
    return { sent: true, id: data?.id, provider: 'resend' }
  }

  return { sent: false, reason: 'no-mailer' }
}

function verificationEmailMail({ name, verifyUrl }) {
  const safeName = name ? String(name).replace(/</g, '&lt;').replace(/>/g, '&gt;') : 'Cher client'
  return {
    subject: 'Activez votre compte — Agro Véto Services Congo',
    html: `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Validation de votre compte Agro Véto Services</title>
</head>
<body style="margin: 0; padding: 0; background-color: #070f09; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f4f4f5;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #070f09; width: 100% !important; padding: 40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 580px; background-color: #0f1c13; border: 1px solid rgba(180, 112, 39, 0.35); border-radius: 20px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
          <!-- Header -->
          <tr>
            <td style="padding: 32px 36px; background-color: #15271a; border-bottom: 1px solid rgba(180, 112, 39, 0.25); text-align: left;">
              <span style="font-size: 13px; font-weight: 800; letter-spacing: 0.12em; text-transform: uppercase; color: #b47027; display: block;">Agro Véto Services Congo</span>
              <h1 style="margin: 8px 0 0; font-size: 22px; font-weight: 800; color: #ffffff; letter-spacing: -0.02em;">Activation de votre compte</h1>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td style="padding: 36px 36px 28px;">
              <p style="font-size: 16px; color: #e4e4e7; margin: 0 0 16px; line-height: 1.6;">Bonjour <strong>${safeName}</strong>,</p>
              <p style="font-size: 15px; color: #a1a1aa; margin: 0 0 24px; line-height: 1.65;">
                Merci d'avoir créé votre compte sur <strong>Agro Véto Services Congo</strong>. Pour sécuriser votre espace éleveur et accéder à vos commandes, rendez-vous cliniques et formations, veuillez confirmer votre adresse email.
              </p>

              <!-- CTA Button -->
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: 28px 0 32px;">
                <tr>
                  <td align="center" style="border-radius: 12px; background: #b47027;">
                    <a href="${verifyUrl}" target="_blank" style="font-size: 15px; font-weight: 700; color: #ffffff; text-decoration: none; padding: 14px 32px; display: inline-block; border-radius: 12px; letter-spacing: 0.02em;">
                      Valider mon adresse email &rarr;
                    </a>
                  </td>
                </tr>
              </table>

              <p style="font-size: 13px; color: #71717a; margin: 0 0 16px; line-height: 1.6;">
                Ce lien de confirmation est valable pendant <strong>24 heures</strong>. Si vous n'êtes pas à l'origine de cette inscription, vous pouvez simplement ignorer ce message.
              </p>

              <!-- Fallback Link -->
              <div style="padding: 14px; background-color: #070f09; border-radius: 10px; border: 1px solid rgba(255,255,255,0.06); margin-top: 24px;">
                <p style="font-size: 12px; color: #71717a; margin: 0 0 6px;">Si le bouton ne fonctionne pas, copiez-collez ce lien :</p>
                <a href="${verifyUrl}" target="_blank" style="font-size: 12px; color: #b47027; word-break: break-all; text-decoration: underline;">${verifyUrl}</a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 36px; background-color: #0b150e; border-top: 1px solid rgba(255,255,255,0.06); text-align: center;">
              <p style="font-size: 12px; color: #52525b; margin: 0; line-height: 1.5;">
                Agro Véto Services Congo &bull; Santé animale, nutrition et formations agropastorales<br>
                Pointe-Noire &amp; Brazzaville, République du Congo
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`,
  }
}

function resetPasswordMail({ name, resetUrl }) {
  const safeName = name ? String(name).replace(/</g, '&lt;').replace(/>/g, '&gt;') : 'Cher client'
  return {
    subject: 'Réinitialisation de votre mot de passe — Agro Véto Services',
    html: `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Réinitialisation de votre mot de passe</title>
</head>
<body style="margin: 0; padding: 0; background-color: #070f09; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f4f4f5;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #070f09; width: 100% !important; padding: 40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 580px; background-color: #0f1c13; border: 1px solid rgba(180, 112, 39, 0.35); border-radius: 20px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
          <tr>
            <td style="padding: 32px 36px; background-color: #15271a; border-bottom: 1px solid rgba(180, 112, 39, 0.25); text-align: left;">
              <span style="font-size: 13px; font-weight: 800; letter-spacing: 0.12em; text-transform: uppercase; color: #b47027; display: block;">Agro Véto Services Congo</span>
              <h1 style="margin: 8px 0 0; font-size: 22px; font-weight: 800; color: #ffffff;">Nouveau mot de passe</h1>
            </td>
          </tr>
          <tr>
            <td style="padding: 36px 36px 28px;">
              <p style="font-size: 16px; color: #e4e4e7; margin: 0 0 16px; line-height: 1.6;">Bonjour <strong>${safeName}</strong>,</p>
              <p style="font-size: 15px; color: #a1a1aa; margin: 0 0 24px; line-height: 1.65;">
                Vous avez demandé la réinitialisation de votre mot de passe pour accéder à votre espace AVS. Cliquez sur le bouton ci-dessous pour en définir un nouveau :
              </p>
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: 28px 0 32px;">
                <tr>
                  <td align="center" style="border-radius: 12px; background: #b47027;">
                    <a href="${resetUrl}" target="_blank" style="font-size: 15px; font-weight: 700; color: #ffffff; text-decoration: none; padding: 14px 32px; display: inline-block; border-radius: 12px;">
                      Réinitialiser mon mot de passe &rarr;
                    </a>
                  </td>
                </tr>
              </table>
              <p style="font-size: 13px; color: #71717a; margin: 0 0 16px;">Ce lien est valable pendant <strong>1 heure</strong>. Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer ce message.</p>
              <div style="padding: 14px; background-color: #070f09; border-radius: 10px; border: 1px solid rgba(255,255,255,0.06); margin-top: 24px;">
                <p style="font-size: 12px; color: #71717a; margin: 0 0 6px;">Lien direct :</p>
                <a href="${resetUrl}" target="_blank" style="font-size: 12px; color: #b47027; word-break: break-all;">${resetUrl}</a>
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding: 24px 36px; background-color: #0b150e; border-top: 1px solid rgba(255,255,255,0.06); text-align: center;">
              <p style="font-size: 12px; color: #52525b; margin: 0;">Agro Véto Services Congo &bull; Pointe-Noire &amp; Brazzaville</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`,
  }
}

module.exports = {
  sendMail,
  verificationEmailMail,
  resetPasswordMail,
  hasMailer: () => Boolean(RESEND_API_KEY),
  isProd: () => NODE_ENV === 'production',
}
