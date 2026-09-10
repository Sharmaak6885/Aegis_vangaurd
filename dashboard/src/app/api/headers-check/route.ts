import { NextResponse } from "next/server";

export async function GET() {
  // Simulate a live scan delay
  await new Promise((resolve) => setTimeout(resolve, 2000));

  // We could implement an actual fetch here in a real scenario,
  // but for the static dashboard we return a mock response that
  // mirrors the expected scanner output.
  return NextResponse.json({
    "app.archscale.in": {
      "Strict-Transport-Security": "missing",
      "Content-Security-Policy": "missing",
      "X-Frame-Options": "missing",
      "X-Content-Type-Options": "missing",
      "Referrer-Policy": "missing",
      "Permissions-Policy": "missing",
      "X-XSS-Protection": "missing",
      "X-Permitted-Cross-Domain-Policies": "missing",
    },
    "auth.archscale.in": {
      "Strict-Transport-Security": "missing",
      "Content-Security-Policy": "missing",
      "X-Frame-Options": "missing",
      "X-Content-Type-Options": "missing",
      "Referrer-Policy": "missing",
      "Permissions-Policy": "missing",
      "X-XSS-Protection": "missing",
      "X-Permitted-Cross-Domain-Policies": "missing",
    }
  });
}
