import "server-only";

// Basta tenerlo in memoria: il sito gira in un solo processo.
const WINDOW_MS = 15 * 60_000;
const MAX_PER_ACCOUNT = 5;
const MAX_PER_ADDRESS = 20;

const failures = new Map<string, { count: number; resetAt: number }>();

function read(key: string, now: number) {
  const entry = failures.get(key);
  if (!entry || entry.resetAt <= now) return null;
  return entry;
}

function bump(key: string, now: number) {
  const entry = read(key, now);
  if (entry) entry.count += 1;
  else failures.set(key, { count: 1, resetAt: now + WINDOW_MS });
}

/** Minuti da attendere prima di riprovare, oppure 0 se il tentativo è ammesso. */
export function lockedMinutes(address: string, username: string) {
  const now = Date.now();
  const account = read(`u:${address}:${username.toLowerCase()}`, now);
  const source = read(`a:${address}`, now);
  const blocked = [
    account && account.count >= MAX_PER_ACCOUNT ? account : null,
    source && source.count >= MAX_PER_ADDRESS ? source : null,
  ].filter((entry) => entry !== null);

  if (blocked.length === 0) return 0;
  return Math.ceil((Math.max(...blocked.map((entry) => entry.resetAt)) - now) / 60_000);
}

export function recordFailure(address: string, username: string) {
  const now = Date.now();
  if (failures.size > 5000) {
    for (const [key, entry] of failures) if (entry.resetAt <= now) failures.delete(key);
  }
  bump(`u:${address}:${username.toLowerCase()}`, now);
  bump(`a:${address}`, now);
}

export function clearFailures(address: string, username: string) {
  failures.delete(`u:${address}:${username.toLowerCase()}`);
}
