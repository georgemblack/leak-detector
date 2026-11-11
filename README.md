# Leak detector

A small request counter for an isolated Access service-token experiment. One Worker
serves server-rendered HTML; one SQLite-backed Durable Object stores one row per
accepted request. No frontend dependencies, external assets, or automatic polling.

- Worker: `super-secret-resource`
- Account: `bc4564dd499c0a9b8a7bb79c9bd5ea6d`
- URL: `https://super-secret-resource.georgeblack.workers.dev`

Preview URLs are disabled.

## Develop and test

```sh
pnpm install
pnpm check
pnpm test
pnpm dev --var ALLOW_UNPROTECTED:true
```

## Initial unprotected deployment

```sh
pnpm exec wrangler deploy --var ALLOW_UNPROTECTED:true
```

This explicitly overrides the fail-closed default for the first live test. The
dashboard displays a warning while this bypass is active. All paths and methods
that reach the Worker are counted, including dashboard refreshes, HEAD requests,
and requests for missing assets. The response includes the current request.

## Enable Access after testing

1. Create the Access application covering this Worker and allow the dedicated
   service token (and your own identity if you want browser access).
2. Set `ACCESS_AUD` in `wrangler.jsonc` to that application's audience tag.
3. Deploy with `pnpm deploy`, without the temporary bypass override.
4. Verify the dedicated token succeeds and missing/invalid credentials do not.
   Also verify other ingress routes cannot bypass protection.
5. Reset the disposable test data before starting the experiment.

The fetch handler checks `ctx.access` and its audience **before calling the Durable
Object**. Missing context, an empty configured AUD, or a different audience returns
403. Access authenticates before Worker invocation; the handler provides the
additional fail-closed check. It does not trust client-supplied identity headers.
No Static Assets binding is used because it would prevent this Worker from
receiving `ctx.access`.

Access-blocked requests never invoke this Worker and therefore are not recorded.
Test-mode and authenticated totals are tracked separately. Do not share a token
that grants access to any other resource. Revoke the experiment token afterward.

## Stored metadata

Each row contains UTC time, method, path (up to 1,024 characters), connecting IP,
Cloudflare colo/airport code, country, city, region, ASN, ASN organization,
User-Agent, HTTP and TLS versions, and Access-authenticated state/audience.
Other text fields are capped at 512 characters. Query strings, request bodies,
cookies, credentials, and arbitrary headers are not collected. Avoid putting
secrets in URL paths or User-Agent strings.

The dashboard shows lifetime totals, last-24-hour count, unique IPs, authenticated
count, top 10 colos/countries/ASNs, and the last 20 requests. It does not display
stored IP addresses or User-Agents. Anyone allowed to reach the resource can
read the dashboard, including users of the experiment token.

`cf.colo` is the Cloudflare edge location, not the visitor's airport. Geography
comes from IP metadata and is approximate. Data is retained until explicitly
reset. There is no public reset endpoint. A single object and full-table summary
queries keep this simple; this is for a small experiment, not a high-volume
analytics service. Sustained traffic increases storage and request costs.

## References

Authoritative local docs used:

- `../cloudflare-docs/src/content/docs/workers/configuration/cloudflare-access.mdx`
- `../cloudflare-docs/src/content/docs/durable-objects/api/sqlite-storage-api.mdx`
