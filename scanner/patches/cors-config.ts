import cors from 'cors';

/**
 * Patch for CORS Misconfiguration.
 * Replaces wildcard origins and null-origin acceptance with a strict whitelist.
 */
const allowedOrigins = [
  'https://app.archscale.in',
  'https://admin.archscale.in',
  // Add other legitimate client URLs
];

export const strictCorsMiddleware = cors({
  origin: (origin, callback) => {
    // allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true, // Allow cookies to be sent
  maxAge: 86400, // Cache preflight requests for 24 hours
});

// Usage in Express:
// app.use(strictCorsMiddleware);
