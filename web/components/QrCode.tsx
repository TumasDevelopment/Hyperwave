import qrcode from "qrcode-generator";

/**
 * Codice QR in SVG, disegnato qui: il segreto non passa da servizi esterni.
 * Un unico <path> con un quadrato per ogni modulo scuro, più il margine bianco richiesto.
 */
export function QrCode({ text, size = 200, label }: { text: string; size?: number; label: string }) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const count = qr.getModuleCount();
  const quiet = 4;
  const total = count + quiet * 2;
  let d = "";
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) d += `M${col + quiet},${row + quiet}h1v1h-1z`;
    }
  }
  return (
    <svg
      className="qr"
      width={size}
      height={size}
      viewBox={`0 0 ${total} ${total}`}
      shapeRendering="crispEdges"
      role="img"
      aria-label={label}
    >
      <rect width={total} height={total} fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  );
}
