import { env } from "cloudflare:workers";
import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { beforeEach, expect, it } from "vitest";
import worker from "../src/index";

const stub = () => env.REQUEST_LOG.getByName("all-requests");
const rows = () => runInDurableObject(stub(), (_instance, state) =>
  state.storage.sql.exec("SELECT * FROM requests ORDER BY id").toArray());
const context = (aud) => {
  const ctx = createExecutionContext();
  if (aud) Object.defineProperty(ctx, "access", { value: { aud } });
  return ctx;
};
const send = (url = "https://example.com/", options = {}, settings = {}, ctx = context()) =>
  worker.fetch(new Request(url, options), { ...env, ...settings }, ctx);
const publicMode = { ALLOW_UNPROTECTED: "true" };

beforeEach(async () => {
  await runInDurableObject(stub(), (_instance, state) => state.storage.sql.exec("DELETE FROM requests").toArray());
});

it("fails closed without Access, even with forged authentication headers", async () => {
  const response = await send("https://example.com/", {
    headers: { "Cf-Access-Jwt-Assertion": "forged", "Cf-Access-Client-Id": "fake" },
  });
  expect(response.status).toBe(403);
  expect(await rows()).toHaveLength(0);
});

it("rejects missing and incorrect configured audiences before recording", async () => {
  for (const aud of ["", "other-app"]) {
    const response = await send(undefined, {}, { ACCESS_AUD: aud }, context("test-app"));
    expect(response.status).toBe(403);
  }
  expect(await rows()).toHaveLength(0);
});

it("accepts the expected Access audience", async () => {
  const response = await send(undefined, {}, { ACCESS_AUD: "test-app" }, context("test-app"));
  expect(response.status).toBe(200);
  expect(await response.text()).toContain("Protected by Cloudflare Access.");
  expect(await rows()).toEqual([expect.objectContaining({ authenticated: 1, audience: "test-app" })]);
});

it("records metadata and includes the current request in the dashboard", async () => {
  const response = await send("https://example.com/test?secret=excluded", {
    method: "POST",
    body: "secret body",
    headers: {
      "CF-Connecting-IP": "192.0.2.1", "User-Agent": "test-client",
      Authorization: "Bearer excluded", Cookie: "secret=excluded",
    },
    cf: { colo: "LHR", country: "GB", city: "London", region: "England", asn: 64496,
      asOrganization: "Example", httpProtocol: "HTTP/2", tlsVersion: "TLSv1.3" },
  }, publicMode);
  const html = await response.text();
  expect(html).toContain("<strong>1</strong> requests");
  expect(html).toContain("LHR");
  expect(html).toContain("Access protection is temporarily disabled");
  expect(html).not.toContain("192.0.2.1");
  expect(html).not.toContain("excluded");
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(await rows()).toEqual([expect.objectContaining({ method: "POST", path: "/test",
    ip: "192.0.2.1", colo: "LHR", country: "GB", asn: 64496, user_agent: "test-client", authenticated: 0 })]);
  expect(JSON.stringify(await rows())).not.toContain("secret");
});

it("counts all methods and paths, with an empty HEAD response", async () => {
  const head = await send("https://example.com/favicon.ico", { method: "HEAD" }, publicMode);
  expect(head.status).toBe(200);
  expect(await head.text()).toBe("");
  const next = await send(undefined, {}, publicMode);
  expect(await next.text()).toContain("<strong>2</strong> requests");
  expect(await rows()).toHaveLength(2);
});

it("escapes visitor-controlled text and bounds stored fields", async () => {
  const response = await send("https://example.com/", { cf: { colo: "<script>alert(1)</script>" },
    headers: { "User-Agent": "x".repeat(2000) } }, publicMode);
  const html = await response.text();
  expect(html).not.toContain("<script>");
  expect(html).toContain("&lt;script&gt;");
  expect((await rows())[0].user_agent).toHaveLength(512);
});

it("preserves one row per request during concurrent calls", async () => {
  await Promise.all(Array.from({ length: 12 }, () => send(undefined, {}, publicMode)));
  expect(await rows()).toHaveLength(12);
});

it("aggregates locations, distinct IPs, and the last 24 hours", async () => {
  const options = { headers: { "CF-Connecting-IP": "192.0.2.1" },
    cf: { colo: "LHR", country: "GB", asn: 64496 } };
  await send(undefined, options, publicMode);
  await runInDurableObject(stub(), (_instance, state) => state.storage.sql.exec(
    "UPDATE requests SET timestamp = ?", new Date(Date.now() - 172_800_000).toISOString(),
  ).toArray());
  const response = await send(undefined, options, publicMode);
  const html = await response.text();
  expect(html).toContain("<strong>2</strong> requests");
  expect(html).toContain("<strong>1</strong> in the last 24h");
  expect(html).toContain("<strong>1</strong> unique IPs");
  expect(html).toContain("<td>LHR</td><td>2</td>");
  expect(html).toContain("<td>GB</td><td>2</td>");
  expect(html).toContain("<td>64496</td><td>2</td>");
});
