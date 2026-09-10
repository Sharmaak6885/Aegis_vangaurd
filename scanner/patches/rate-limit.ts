import rateLimit from 'express-rate-limit';

/**
 * High-confidence patch for missing rate limiting on authentication endpoints.
 * Prevents credential stuffing and brute-force attacks.
 */
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  message: {
    status: 429,
    error: 'Too many login attempts from this IP, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Usage in Express:
// app.post('/api/auth/login', loginLimiter, loginHandler);
// app.post('/api/auth/register', loginLimiter, registerHandler);
// app.post('/api/auth/forgot-password', loginLimiter, forgotPasswordHandler);
