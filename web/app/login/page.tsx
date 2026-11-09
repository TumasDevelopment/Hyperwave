import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Credito, Logo } from "@/components/Brand";
import { LoginForm } from "@/components/LoginForm";
import { getUser, hasLoginChallenge } from "@/lib/auth";

export const metadata: Metadata = { title: "Accesso" };

export default async function LoginPage() {
  if (await getUser()) redirect("/");
  const step = (await hasLoginChallenge()) ? "totp" : "password";
  return (
    <main className="login">
      <div className="login__box">
        <div className="login__brand">
          <Logo size={40} />
          <div>
            <h1>Hyperwave</h1>
            <p className="muted">Monitoraggio della rete</p>
          </div>
        </div>
        <LoginForm initialStep={step} />
      </div>
      <Credito />
    </main>
  );
}
