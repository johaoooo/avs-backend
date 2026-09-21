// backend/src/routes/authRoutes.js
const express = require('express')
const router = express.Router()
const authController = require('../controllers/authController')
const { authenticate, requireAdmin } = require('../middlewares/auth')
const { validate } = require('../middlewares/validate')
const { authLimiter, sensitiveLimiter } = require('../middlewares/rateLimiters')
const {
  registerSchema,
  loginSchema,
  verifyEmailSchema,
  resendVerificationSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
  updateProfileSchema,
} = require('../validators/authValidators')

router.post('/register', authLimiter, validate(registerSchema), authController.register)
router.post('/login', authLimiter, validate(loginSchema), authController.login)
router.post('/verify-email', sensitiveLimiter, validate(verifyEmailSchema), authController.verifyEmail)
router.get('/verify-email', sensitiveLimiter, authController.verifyEmail)
router.post('/resend-verification', sensitiveLimiter, validate(resendVerificationSchema), authController.resendVerification)
router.post('/forgot-password', sensitiveLimiter, validate(forgotPasswordSchema), authController.forgotPassword)
router.post('/reset-password', sensitiveLimiter, validate(resetPasswordSchema), authController.resetPassword)
router.get('/me', authenticate, authController.getMe)
router.put('/profile', authenticate, validate(updateProfileSchema), authController.updateProfile)
router.put('/password', authenticate, sensitiveLimiter, validate(changePasswordSchema), authController.changePassword)
router.get('/users', authenticate, requireAdmin, authController.listUsers)

module.exports = router
