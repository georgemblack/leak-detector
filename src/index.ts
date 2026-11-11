import { DurableObject } from "cloudflare:workers";

interface Env {
  REQUEST_LOG: DurableObjectNamespace<RequestLog>;
  ALLOW_UNPROTECTED: string;
  ACCESS_AUD: string;
}

interface RequestMetadata {
  timestamp: string;
  method: string;
  path: string;
  ip: string;
  colo: string;
  country: string;
  city: string;
  region: string;
  asn: number | null;
  organization: string;
  userAgent: string;
  protocol: string;
  tls: string;
  authenticated: number;
  audience: string;
}

type Group = { label: string; count: number };
type Recent = { timestamp: string; method: string; path: string; colo: string; country: string; asn: number | null };

export class RequestLog extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        ip TEXT NOT NULL,
        colo TEXT NOT NULL,
        country TEXT NOT NULL,
        city TEXT NOT NULL,
        region TEXT NOT NULL,
        asn INTEGER,
        organization TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        protocol TEXT NOT NULL,
        tls TEXT NOT NULL,
        authenticated INTEGER NOT NULL,
        audience TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS requests_timestamp ON requests(timestamp);
    `);
  }

  record(metadata: RequestMetadata) {
    const sql = this.ctx.storage.sql;
    sql.exec(
      `INSERT INTO requests (timestamp, method, path, ip, colo, country, city, region,
        asn, organization, user_agent, protocol, tls, authenticated, audience)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      metadata.timestamp, metadata.method, metadata.path, metadata.ip, metadata.colo,
      metadata.country, metadata.city, metadata.region, metadata.asn, metadata.organization,
      metadata.userAgent, metadata.protocol, metadata.tls, metadata.authenticated, metadata.audience,
    );

    const totals = sql.exec<{ total: number; unique_ips: number; authenticated: number }>(
      `SELECT COUNT(*) AS total, COUNT(DISTINCT NULLIF(ip, '')) AS unique_ips,
       COALESCE(SUM(authenticated), 0) AS authenticated FROM requests`,
    ).one();
    const last24h = sql.exec<{ count: number }>(
      "SELECT COUNT(*) AS count FROM requests WHERE timestamp >= ?",
      new Date(Date.now() - 86_400_000).toISOString(),
    ).one().count;
    const groupBy = (column: "colo" | "country" | "asn") => sql.exec<Group>(
      `SELECT COALESCE(CAST(${column} AS TEXT), 'Unknown') AS label, COUNT(*) AS count
       FROM requests GROUP BY ${column} ORDER BY count DESC, label LIMIT 10`,
    ).toArray();

    return {
      ...totals,
      last24h,
      colos: groupBy("colo"),
      countries: groupBy("country"),
      asns: groupBy("asn"),
      recent: sql.exec<Recent>(
        "SELECT timestamp, method, path, colo, country, asn FROM requests ORDER BY id DESC LIMIT 20",
      ).toArray(),
    };
  }
}

function escapeHtml(value: unknown): string {
  return String(value ?? "Unknown").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]!);
}

function render(stats: ReturnType<RequestLog["record"]>, unprotected: boolean): string {
  const table = (title: string, rows: Group[]) => `<section><h2>${title}</h2><table>
    <thead><tr><th>Source</th><th>Requests</th></tr></thead><tbody>${rows.map((row) =>
      `<tr><td>${escapeHtml(row.label)}</td><td>${row.count}</td></tr>`,
    ).join("")}</tbody></table></section>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Leak detector</title><link rel="icon" href="data:,">
<style>
body{font:16px system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 20px;color:#222}
h1{margin-bottom:8px}p{color:#555}strong{color:#222}main{display:flex;gap:32px;flex-wrap:wrap}
section{flex:1;min-width:180px}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #ddd;overflow-wrap:anywhere}
.recent{overflow-x:auto}.warning{background:#fff2cc;padding:12px}a{color:inherit}
</style></head><body><h1>Leak detector</h1>
${unprotected ? '<p class="warning">Test mode: Access protection is temporarily disabled.</p>' : '<p>Protected by Cloudflare Access.</p>'}
<p><strong>${stats.total.toLocaleString()}</strong> requests · <strong>${stats.last24h.toLocaleString()}</strong> in the last 24h ·
<strong>${stats.unique_ips.toLocaleString()}</strong> unique IPs · <strong>${stats.authenticated.toLocaleString()}</strong> authenticated</p>
<p>Every request that reaches this page is recorded, including this one. <a href="/">Refresh</a></p>
<main>${table("Cloudflare airports", stats.colos)}${table("Countries", stats.countries)}${table("ASNs", stats.asns)}</main>
<h2>Last 20 requests</h2><div class="recent"><table><thead><tr><th>UTC</th><th>Method</th><th>Path</th><th>Airport</th><th>Country</th><th>ASN</th></tr></thead>
<tbody>${stats.recent.map((row) => `<tr>${[row.timestamp, row.method, row.path, row.colo, row.country, row.asn]
    .map((value) => `<td>${escapeHtml(value)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
<p>Airports are Cloudflare edge locations. Country is IP-derived. No automatic refresh or external assets.</p>
</body></html>`;
}

const responseHeaders = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
};

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const unprotected = env.ALLOW_UNPROTECTED === "true";
    if (!unprotected && (!ctx.access || !env.ACCESS_AUD || ctx.access.aud !== env.ACCESS_AUD)) {
      return new Response("Forbidden", { status: 403, headers: { "cache-control": "no-store" } });
    }

    const cf = request.cf;
    const text = (value: unknown, fallback = "Unknown") => typeof value === "string" ? value.slice(0, 512) : fallback;
    const log = env.REQUEST_LOG.getByName("all-requests");
    const stats = await log.record({
      timestamp: new Date().toISOString(),
      method: request.method,
      path: new URL(request.url).pathname.slice(0, 1024),
      ip: text(request.headers.get("CF-Connecting-IP"), ""),
      colo: text(cf?.colo),
      country: text(cf?.country),
      city: text(cf?.city),
      region: text(cf?.region),
      asn: typeof cf?.asn === "number" ? cf.asn : null,
      organization: text(cf?.asOrganization),
      userAgent: text(request.headers.get("User-Agent"), ""),
      protocol: text(cf?.httpProtocol),
      tls: text(cf?.tlsVersion),
      authenticated: ctx.access ? 1 : 0,
      audience: ctx.access?.aud ?? "",
    });
    return new Response(request.method === "HEAD" ? null : render(stats, unprotected), { headers: responseHeaders });
  },
} satisfies ExportedHandler<Env>;
