import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CoEvolve",
  description: "Adversarial Training as a Service",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="min-h-screen flex">
          <nav className="w-56 border-r border-[--border] p-4 flex flex-col gap-1">
            <div className="text-lg font-bold mb-6">
              <span className="text-brand-red">co</span>
              <span className="text-brand-yellow">evolve</span>
            </div>
            {[
              { href: "/", label: "Dashboard" },
              { href: "/train", label: "Run Training" },
              { href: "/episodes", label: "Episodes" },
              { href: "/rules", label: "Rules" },
              { href: "/elo", label: "Elo Ratings" },
            ].map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="px-3 py-2 rounded text-sm hover:bg-[--surface] transition-colors"
              >
                {link.label}
              </a>
            ))}
          </nav>
          <main className="flex-1 p-6 overflow-auto">{children}</main>
        </div>
      </body>
    </html>
  );
}
