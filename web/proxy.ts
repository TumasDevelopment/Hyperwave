import { NextResponse, type NextRequest } from "next/server";

// Gli script hanno un nonce nuovo a ogni pagina: uno script iniettato non lo conosce e non parte.
// Gli stili restano in linea perché i grafici si posizionano con l'attributo style.
function contentSecurityPolicy(nonce: string) {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

// Controllo rapido: c'è un cookie di sessione? La verifica vera la fanno pagine, API e azioni.
// Pubbliche: la pagina di accesso, /api/salute e /api/v1 (che si autentica con il token API).
const isPublic = (pathname: string) =>
  pathname === "/login" || pathname === "/api/salute" || pathname.startsWith("/api/v1/");

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isApi = pathname.startsWith("/api/");

  if (!isPublic(pathname) && !request.cookies.has("hw_sessione")) {
    if (isApi) return NextResponse.json({ error: "Sessione scaduta" }, { status: 401 });
    return NextResponse.redirect(new URL("/login", request.url));
  }
  if (isApi) return NextResponse.next();

  const policy = contentSecurityPolicy(btoa(crypto.randomUUID()));
  const headers = new Headers(request.headers);
  headers.set("Content-Security-Policy", policy);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|icon.svg|favicon.ico).*)"],
};
