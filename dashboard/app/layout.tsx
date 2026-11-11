import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "Averqon Firewall", description: "Averqon firewall and IDS/IPS console" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en"><body>{children}</body></html>
  );
}
