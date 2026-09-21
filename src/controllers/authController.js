// backend/src/controllers/authController.js
const bcrypt = require('bcryptjs')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const prisma = require('../lib/prisma')
const { JWT_SECRET, JWT_EXPIRES_IN, FRONTEND_URL } = require('../config/env')
const { checkPassword, normalizePhone } = require('../lib/accountPolicy')
const { sendMail, verificationEmailMail, resetPasswordMail, hasMailer, isProd } = require('../lib/mailer')

function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN })
}

exports.register = async (req, res, next) => {
  try {
    const { email, password, name, fullName, phone } = req.body
    const finalName = (name || fullName || '').trim()
    const finalPhone = normalizePhone(phone || '')
    const finalEmail = (email || '').toLowerCase().trim()

    if (!finalName) {
      return res.status(400).json({
        success: false,
        message: 'Champ obligatoire : nom complet',
      })
    }

    if (!finalEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(finalEmail)) {
      return res.status(400).json({
        success: false,
        message: 'Adresse email valide obligatoire pour la confirmation de votre compte.',
      })
    }

    const passwordError = checkPassword(password)
    if (passwordError) {
      return res.status(400).json({ success: false, message: passwordError })
    }

    if ((phone || '').trim() && !finalPhone) {
      return res.status(400).json({
        success: false,
        message: 'Numéro de téléphone invalide (8 à 15 chiffres attendus).',
      })
    }

    const existing = await prisma.user.findFirst({
      where: {
        OR: [
          { email: finalEmail },
          ...(finalPhone ? [{ phone: finalPhone }] : []),
        ],
      },
    })

    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'Un compte existe déjà avec cet email ou ce numéro de téléphone.',
      })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const rawToken = crypto.randomBytes(32).toString('hex')
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24h

    const user = await prisma.user.create({
      data: {
        email: finalEmail,
        password: hashedPassword,
        name: finalName,
        phone: finalPhone || null,
        role: 'CLIENT',
        emailVerified: false,
        emailVerificationToken: tokenHash,
        emailVerificationExpires: verificationExpires,
      },
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        emailVerified: true,
        createdAt: true,
      },
    })

    const origin = req.get('origin') || FRONTEND_URL || 'http://localhost:3003'
    const verifyUrl = `${origin.replace(/\/+$/, '')}/verifier-email?token=${rawToken}`
    const mail = verificationEmailMail({ name: user.name, verifyUrl })

    if (hasMailer()) {
      try {
        await sendMail({ to: user.email, subject: mail.subject, html: mail.html })
      } catch (mailError) {
        console.error('[Auth] Échec envoi email validation:', mailError.message)
      }
    } else {
      console.info(`[Auth] [DEV] Lien de validation pour ${user.email} : ${verifyUrl}`)
    }

    let devVerifyUrl = null
    if (!hasMailer()) {
      devVerifyUrl = verifyUrl
    }

    res.status(201).json({
      success: true,
      requiresVerification: true,
      email: user.email,
      message: 'Compte créé avec succès ! Un email de confirmation a été envoyé à votre adresse email. Veuillez cliquer sur le lien reçu pour activer votre compte.',
      data: {
        user,
        requiresVerification: true,
        ...(devVerifyUrl ? { devVerifyUrl } : {}),
      },
    })
  } catch (error) {
    next(error)
  }
}

exports.login = async (req, res, next) => {
  try {
    const { email, phone, identifier, password } = req.body
    const loginId = (identifier || email || phone || '').toLowerCase().trim()
    const loginPhone = normalizePhone(identifier || phone || '') || ''

    if (!loginId || !password) {
      return res.status(400).json({
        success: false,
        message: 'Veuillez renseigner votre email ou téléphone et mot de passe',
      })
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: loginId },
          { phone: loginId },
          { phone: loginId.replace(/\s+/g, '') },
          ...(loginPhone ? [{ phone: loginPhone }] : []),
        ],
      },
    })

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Identifiants invalides ou compte inactif',
      })
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Identifiants invalides',
      })
    }

    if (!user.emailVerified) {
      return res.status(403).json({
        success: false,
        requiresVerification: true,
        email: user.email,
        message: 'Veuillez valider votre adresse email avant d’accéder à votre compte. Un lien de confirmation vous a été envoyé par email.',
      })
    }

    const token = generateToken(user.id)

    res.json({
      success: true,
      message: 'Connexion réussie',
      data: {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          phone: user.phone,
          role: user.role,
          avatar: user.avatar,
          emailVerified: user.emailVerified,
        },
        token,
      },
    })
  } catch (error) {
    next(error)
  }
}

// ── Validation de l'adresse email par jeton (token)
exports.verifyEmail = async (req, res, next) => {
  try {
    const token = req.body?.token || req.query?.token
    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Jeton de validation manquant ou invalide.',
      })
    }

    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex')
    const user = await prisma.user.findFirst({
      where: {
        emailVerificationToken: tokenHash,
        emailVerificationExpires: { gt: new Date() },
      },
    })

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Le lien de validation est invalide ou a expiré (validité de 24 heures). Veuillez faire une nouvelle demande.',
      })
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerificationToken: null,
        emailVerificationExpires: null,
        isActive: true,
      },
    })

    const sessionToken = generateToken(user.id)

    res.json({
      success: true,
      message: 'Votre adresse email a été validée avec succès ! Vous pouvez maintenant accéder à votre compte.',
      data: {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          phone: user.phone,
          role: user.role,
          avatar: user.avatar,
          emailVerified: true,
        },
        token: sessionToken,
      },
    })
  } catch (error) {
    next(error)
  }
}

// ── Renvoyer un email de validation
exports.resendVerification = async (req, res, next) => {
  try {
    const { email, phone, identifier } = req.body
    const loginId = (identifier || email || phone || '').toLowerCase().trim()
    const loginPhone = normalizePhone(identifier || phone || '') || ''

    if (!loginId && !loginPhone) {
      return res.status(400).json({
        success: false,
        message: 'Veuillez renseigner votre adresse email.',
      })
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: loginId },
          ...(loginPhone ? [{ phone: loginPhone }] : []),
        ],
      },
    })

    const genericMessage = 'Si ce compte existe et n’est pas encore validé, un nouveau lien de validation vient d’être envoyé par email.'

    if (!user) {
      return res.json({ success: true, message: genericMessage })
    }

    if (user.emailVerified) {
      return res.json({
        success: true,
        alreadyVerified: true,
        message: 'Cette adresse email est déjà validée. Vous pouvez vous connecter directement.',
      })
    }

    const rawToken = crypto.randomBytes(32).toString('hex')
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')

    await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerificationToken: tokenHash,
        emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    })

    const origin = req.get('origin') || FRONTEND_URL || 'http://localhost:3003'
    const verifyUrl = `${origin.replace(/\/+$/, '')}/verifier-email?token=${rawToken}`
    const mail = verificationEmailMail({ name: user.name, verifyUrl })

    if (hasMailer()) {
      try {
        await sendMail({ to: user.email, subject: mail.subject, html: mail.html })
      } catch (mailError) {
        console.error('[Auth] Échec envoi email validation:', mailError.message)
      }
    } else {
      console.info(`[Auth] [DEV] Lien de validation pour ${user.email} : ${verifyUrl}`)
    }

    let devVerifyUrl = null
    if (!hasMailer()) {
      devVerifyUrl = verifyUrl
    }

    res.json({
      success: true,
      message: `Un nouveau lien de validation a été envoyé à l'adresse ${user.email}.`,
      ...(devVerifyUrl ? { devVerifyUrl } : {}),
    })
  } catch (error) {
    next(error)
  }
}

exports.getMe = async (req, res, next) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        avatar: true,
        emailVerified: true,
        createdAt: true,
        orders: {
          orderBy: { createdAt: 'desc' },
          take: 5,
        },
        appointments: {
          orderBy: { appointmentDate: 'desc' },
          take: 5,
        },
      },
    })

    res.json({ success: true, data: user })
  } catch (error) {
    next(error)
  }
}

exports.updateProfile = async (req, res, next) => {
  try {
    const { name, phone, avatar } = req.body

    if (phone !== undefined && phone !== null && String(phone).trim() && !normalizePhone(phone)) {
      return res.status(400).json({
        success: false,
        message: 'Numéro de téléphone invalide (8 à 15 chiffres attendus).',
      })
    }

    const updated = await prisma.user.update({
      where: { id: req.user.id },
      data: {
        ...(name && { name: name.trim() }),
        ...(phone !== undefined && { phone: phone ? normalizePhone(phone) : null }),
        ...(avatar !== undefined && { avatar }),
      },
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        avatar: true,
        emailVerified: true,
      },
    })

    res.json({ success: true, message: 'Profil mis à jour', data: updated })
  } catch (error) {
    next(error)
  }
}

exports.changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Veuillez renseigner l’ancien et le nouveau mot de passe',
      })
    }

    const passwordError = checkPassword(newPassword)
    if (passwordError) {
      return res.status(400).json({ success: false, message: passwordError })
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id } })
    const isMatch = await bcrypt.compare(currentPassword, user.password)
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Mot de passe actuel incorrect' })
    }

    const hashed = await bcrypt.hash(newPassword, 10)
    await prisma.user.update({
      where: { id: req.user.id },
      data: { password: hashed },
    })

    res.json({ success: true, message: 'Mot de passe modifié avec succès' })
  } catch (error) {
    next(error)
  }
}

exports.listUsers = async (req, res, next) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        emailVerified: true,
        isActive: true,
        createdAt: true,
        _count: { select: { orders: true, appointments: true } },
      },
      orderBy: { createdAt: 'desc' },
    })

    res.json({ success: true, count: users.length, data: users })
  } catch (error) {
    next(error)
  }
}

// ── Mot de passe oublié : demande de lien (réponse générique anti-énumération)
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email, phone, identifier } = req.body
    const loginId = (identifier || email || phone || '').toLowerCase().trim()
    const loginPhone = normalizePhone(identifier || phone || '') || ''
    const genericMessage = 'Si un compte existe avec ces informations, un lien de réinitialisation vient de lui être envoyé.'

    if (loginId) {
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { email: loginId },
            { phone: loginId },
            ...(loginPhone ? [{ phone: loginPhone }] : []),
          ],
        },
      })

      if (user && user.isActive && user.email && !user.email.endsWith('@agrovetoservices.cg')) {
        const rawToken = crypto.randomBytes(32).toString('hex')
        const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')

        await prisma.user.update({
          where: { id: user.id },
          data: {
            passwordResetToken: tokenHash,
            passwordResetExpires: new Date(Date.now() + 60 * 60 * 1000),
          },
        })

        const origin = req.get('origin') || FRONTEND_URL || 'http://localhost:3003'
        const resetUrl = `${origin.replace(/\/+$/, '')}/mot-de-passe-oublie?token=${rawToken}`
        const mail = resetPasswordMail({ name: user.name, resetUrl })

        if (hasMailer()) {
          try {
            await sendMail({ to: user.email, subject: mail.subject, html: mail.html })
          } catch (mailError) {
            console.error('[Auth] Échec envoi email reset:', mailError.message)
          }
        } else {
          console.info(`[Auth] [DEV] Lien de réinitialisation pour ${user.email} : ${resetUrl}`)
        }

        if (!isProd() && !hasMailer()) {
          return res.json({ success: true, message: genericMessage, devResetUrl: resetUrl })
        }
      }
    }

    res.json({ success: true, message: genericMessage })
  } catch (error) {
    next(error)
  }
}

// ── Mot de passe oublié : application du nouveau mot de passe
exports.resetPassword = async (req, res, next) => {
  try {
    const { token, password: newPassword } = req.body

    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Lien invalide : token et nouveau mot de passe requis.',
      })
    }

    const passwordError = checkPassword(newPassword)
    if (passwordError) {
      return res.status(400).json({ success: false, message: passwordError })
    }

    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex')
    const user = await prisma.user.findUnique({ where: { passwordResetToken: tokenHash } })

    if (!user || !user.passwordResetExpires || user.passwordResetExpires < new Date()) {
      return res.status(400).json({
        success: false,
        message: 'Lien expiré ou invalide. Veuillez refaire une demande.',
      })
    }

    const hashed = await bcrypt.hash(newPassword, 10)
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashed, passwordResetToken: null, passwordResetExpires: null },
    })

    res.json({ success: true, message: 'Mot de passe réinitialisé. Vous pouvez vous connecter.' })
  } catch (error) {
    next(error)
  }
}

// ── Connexion / Inscription Google OAuth (Google Identity Services)
exports.googleAuth = async (req, res, next) => {
  try {
    const { credential } = req.body
    if (!credential) {
      return res.status(400).json({
        success: false,
        message: 'Jeton d’authentification Google manquant.',
      })
    }

    // Vérification sécurisée du jeton auprès de l’API officielle Google OAuth2
    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`)
    if (!googleRes.ok) {
      return res.status(401).json({
        success: false,
        message: 'Jeton Google invalide ou expiré.',
      })
    }

    const payload = await googleRes.json()
    const { sub: googleId, email, name, picture, email_verified } = payload

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Impossible de récupérer l’adresse email associée à ce compte Google.',
      })
    }

    const normalizedEmail = email.toLowerCase().trim()

    // 1. Recherche de l'utilisateur par googleId ou par email
    let user = await prisma.user.findFirst({
      where: {
        OR: [
          { googleId },
          { email: normalizedEmail },
        ],
      },
    })

    if (user) {
      // Si l'utilisateur existait déjà, on lie son compte Google et valide son email
      const updates = {}
      if (!user.googleId) updates.googleId = googleId
      if (!user.emailVerified) updates.emailVerified = true
      if (!user.avatar && picture) updates.avatar = picture
      if (Object.keys(updates).length > 0) {
        user = await prisma.user.update({
          where: { id: user.id },
          data: updates,
        })
      }
    } else {
      // 2. Création automatique du compte Google (directement actif et vérifié)
      const randomPassword = crypto.randomBytes(24).toString('hex')
      const hashedPassword = await bcrypt.hash(randomPassword, 10)

      user = await prisma.user.create({
        data: {
          email: normalizedEmail,
          password: hashedPassword,
          name: name || 'Utilisateur Google',
          googleId,
          avatar: picture || null,
          role: 'CLIENT',
          emailVerified: true,
        },
      })
    }

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Ce compte a été désactivé. Veuillez contacter le support.',
      })
    }

    const token = generateToken(user.id)

    const userSafe = {
      id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      role: user.role,
      avatar: user.avatar,
      emailVerified: user.emailVerified,
      createdAt: user.createdAt,
    }

    res.status(200).json({
      success: true,
      message: 'Connexion avec Google réussie !',
      data: {
        token,
        user: userSafe,
      },
    })
  } catch (error) {
    next(error)
  }
}
