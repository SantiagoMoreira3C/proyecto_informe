import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ALTURA NEXO",
  description: "Asistente para informes de ALTURA",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
