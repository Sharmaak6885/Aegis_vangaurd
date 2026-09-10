import helmet from 'helmet';

/**
 * Patch for missing HTTP Security Headers.
 * This fixes missing HSTS, X-Content-Type-Options, X-Frame-Options, etc.
 */
export const securityHeadersMiddleware = helmet({
  // Force HTTPS and prevent downgrade attacks
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  // Prevent MIME-sniffing
  contentSecurityPolicy: false, // Handled separately in csp-nextjs.ts
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' }, // Prevent Clickjacking (replaces X-Frame-Options)
  hidePoweredBy: true, // Removes X-Powered-By: Express
  ieNoOpen: true,
  noSniff: true, // Sets X-Content-Type-Options: nosniff
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true // Sets X-XSS-Protection: 1; mode=block
});

// Usage in Express:
// app.use(securityHeadersMiddleware);
