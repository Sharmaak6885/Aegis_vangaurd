/**
 * Patch for Cookie Security.
 * Ensures cookies are protected against XSS (HttpOnly), CSRF (SameSite), and sniffing (Secure).
 */

// Example: Express session configuration
import session from 'express-session';

export const secureSessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'fallback_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true in production
    httpOnly: true, // Prevent JS access to cookie
    sameSite: 'strict', // Prevent CSRF
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    // Consider adding __Host- prefix to cookie name if on root path
    // name: '__Host-session'
  }
});

// Example: Setting a custom JWT cookie in Express
/*
res.cookie('__Host-jwt', token, {
  secure: true,
  httpOnly: true,
  sameSite: 'strict',
  path: '/', // Required for __Host- prefix
  maxAge: 3600000 // 1 hour
});
*/
