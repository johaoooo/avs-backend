// backend/src/validators/authValidators.js
// Schémas Zod (messages FR) pour les endpoints d'authentification.
// Réutilise la politique mot de passe partagée (8 min, lettre + chiffre).
const { z } = require('zod')
const { PASSWORD_MIN_LENGTH } = require('../lib/accountPolicy')

const passwordSchema = z
  .string({ error: 'Le mot de passe est obligatoire.' })
  .min(PASSWORD_MIN_LENGTH, `Le mot de passe doit contenir au moins ${PASSWORD_MIN_LENGTH} caractères.`)
  .refine((v) => /[A-Za-z]/.test(v) && /[0-9]/.test(v), {
    message: 'Le mot de passe doit contenir au moins une lettre et un chiffre.',
  })

const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email('Adresse email invalide.')
  .optional()

const requiredEmailSchema = z
  .string({ required_error: 'L’adresse email est obligatoire.' })
  .trim()
  .toLowerCase()
  .email('Adresse email invalide.')

const phoneSchema = z.string().trim().min(1).max(25).optional()

const registerSchema = z.object({
  name: z.string().trim().min(2, 'Le nom doit contenir au moins 2 caractères.').max(120).optional(),
  fullName: z.string().trim().min(2).max(120).optional(),
  email: requiredEmailSchema,
  phone: phoneSchema,
  password: passwordSchema,
})

const loginSchema = z.object({
  identifier: z.string().trim().min(1, 'Identifiant requis.').max(160).optional(),
  email: emailSchema,
  phone: phoneSchema,
  password: z.string().min(1, 'Mot de passe requis.'),
})

const verifyEmailSchema = z.object({
  token: z.string().min(10, 'Jeton de validation manquant ou invalide.'),
})

const resendVerificationSchema = z.object({
  identifier: z.string().trim().min(1).max(160).optional(),
  email: emailSchema,
  phone: phoneSchema,
})

const forgotPasswordSchema = z.object({
  identifier: z.string().trim().min(1).max(160).optional(),
  email: emailSchema,
  phone: phoneSchema,
})

const resetPasswordSchema = z.object({
  token: z.string().min(10, 'Lien invalide.'),
  password: passwordSchema,
})

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Mot de passe actuel requis.'),
  newPassword: passwordSchema,
})

const updateProfileSchema = z.object({
  name: z.string().trim().min(2).max(120).optional(),
  phone: phoneSchema.nullable(),
  avatar: z.string().trim().max(2000).nullable().optional(),
})

module.exports = {
  registerSchema,
  loginSchema,
  verifyEmailSchema,
  resendVerificationSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
  updateProfileSchema,
}
