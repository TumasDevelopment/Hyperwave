import { getUser } from "@/lib/auth";
import { nats } from "@/lib/nats";

export const dynamic = "force-dynamic";

// Ponte tra NATS (hw.live.>) e il browser con Server-Sent Events.
// Nome dell'evento = ultima parte del soggetto: state, rate, flows, event.
export async function GET(request: Request) {
  const user = await getUser();
  if (!user) return new Response("Sessione scaduta", { status: 401 });

  let nc;
  try {
    nc = await nats();
  } catch {
    return new Response("Flusso in tempo reale non disponibile", { status: 503 });
  }

  const encoder = new TextEncoder();
  const sub = nc.subscribe("hw.live.>");
  let keepAlive: ReturnType<typeof setInterval> | undefined;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (text: string) => {
        try {
          controller.enqueue(encoder.encode(text));
        } catch {
          // il browser ha chiuso
        }
      };
      send("retry: 5000\n\n");
      keepAlive = setInterval(() => send(": attivo\n\n"), 20_000);
      const close = () => {
        clearInterval(keepAlive);
        sub.unsubscribe();
        try {
          controller.close();
        } catch {}
      };
      request.signal.addEventListener("abort", close);
      for await (const message of sub) {
        const name = message.subject.slice("hw.live.".length);
        if (name === "rate") continue; // per sensore: la pagina usa lo stato complessivo
        send(`event: ${name}\ndata: ${message.string()}\n\n`);
      }
    },
    cancel() {
      clearInterval(keepAlive);
      sub.unsubscribe();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
