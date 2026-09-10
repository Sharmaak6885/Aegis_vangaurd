import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Sidebar from "@/components/Sidebar";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: "AS-09 Security Audit Dashboard | ArchScale Platform",
  description:
    "Comprehensive security posture assessment of the ArchScale multi-tenant platform. Unauthenticated attack surface analysis, OAuth misconfiguration testing, and infrastructure hardening recommendations.",
  keywords: "security audit, penetration testing, ArchScale, multi-tenant security, OWASP",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} font-sans antialiased`}>
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <main className="flex-1 overflow-y-auto bg-grid">
            <div className="min-h-screen">{children}</div>
          </main>
        </div>
      </body>
    </html>
  );
}
