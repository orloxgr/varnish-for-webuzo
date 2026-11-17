# Scoped WordPress control protocol 1

This defines the common native-panel/WordPress interface. A build must advertise
`capabilities.scopedCookiePolicies: true` only when its actual PHP, drop-in and
configured static consumers execute the choices. A table, stored option or proxy
hash alone does not provide that capability. Basic remains independent of it.

## Explicit connection and authentication

The account owner explicitly configures this website's endpoint:
`POST /wp-json/ultracache/v1/cookie-policy-control`. Native inventory authorizes
the primary hostname or owned alias; the URL's hostname is the signed host.
Credentials in URLs, other hosts, arbitrary paths, queries and redirects are
refused. Existing HTTP-only sites and valid explicit ports remain supported.
HTTPS uses normal certificate verification. The key is the already configured
per-site Varnish token, never a global administrator credential.

Compact UTF-8 JSON request:

```json
{
  "protocol": 1,
  "operation": "status|prepare|commit|rollback",
  "host": "example.test",
  "requestId": "32 lowercase hexadecimal characters",
  "expires": 1794910000,
  "baseDigest": "previous active digest, or empty for initial status",
  "policy": {
    "schemaVersion": 1,
    "central": {"schemaVersion": 1, "rules": []},
    "site": {"schemaVersion": 1, "rules": []}
  }
}
```

`X-UltraCache-Cookie-Control-Signature` is `v1=` followed by HMAC-SHA256 of
these newline-separated fields (no trailing newline):

```text
ultracache-cookie-control-v1
POST
/wp-json/ultracache/v1/cookie-policy-control
<host>
<requestId>
<expires>
<lowercase SHA256 of exact request body bytes>
```

The short MAC validity protects request authentication/replay. It never expires
a running operation or cancels a staged transaction. Each control request gets
a fresh expiry/MAC; the transaction request ID remains stable across retries.
No visitor cookie values, issuance permission or public-cache approval comes
from this transport. Public browser headers cannot impersonate it.

## Materialized defaults without a wire-schema change

For connected apply, native adapters call `materialized_snapshot(central,site)`:
`central` contains versioned bundled defaults underneath explicit admin choices;
`site` contains concrete site choices. Rule fields and schema 1 are unchanged.
Descriptions and provenance remain outside execution/digest semantics. The same
resolved rule list is compiled natively and executed by the application.
`shared/cookie-defaults.json` supplies the standalone application's identical
bundled rules. A nonempty panel-managed committed snapshot remains authoritative until
the next ordinary signed commit, even if application code has newer defaults.

`automatic` remains accepted for old snapshots/recovery. New native targets
materialize it to an identical/covering bundled match or Variant, never the first
child of a prefix. New editors offer Shared/Variant/Private only. Unicode match
lengths sort by UTF-8 bytes in all consumers. Literal names must be nonempty,
trimmed and exclude controls/DEL, ; = double quotes and braces; every consumer
escapes literals for its own language (including Apache argument whitespace).

`snapshot()` with no choices still means an actual empty clear/disconnect;
never inject bundled rules into that recovery operation. A genuinely empty signed clear releases managed runtime ownership while
retaining the empty policy and transaction request identity. Standalone bundled
rules resume; the informational runtime digest is separate from the signed
empty activeDigest. Rollback restores the previous ownership and frozen policy.

## Digests and authenticated replies

The effective digest is SHA256 of canonical JSON with sorted keys, compact
separators and ASCII escaping: `{host, rules}`. Rules are the ordered result of
the common resolver, projected to `scope`, `match`, `action`. IDs/descriptions
are metadata and do not change this digest. Site precedes central; exact then
longest prefix applies within a scope. Core application privacy still wins.

A reply identifies `ok`, integer `protocol`, `operation`, `requestId`, `host`,
and the actual `activeDigest`; prepare/commit also identify `targetDigest`.
Errors identify their concrete stage without echoing tokens or private values.
Status capabilities describe actual available consumers.
An authenticated error may include a literal `code` (lowercase letters, digits,
underscores or hyphens, starting with a letter). The native error retains that
specific cause with the stage and HTTP status; it does not echo free-form origin
messages or malformed codes that could contain visitor values or credentials.

The exact response JSON bytes have two authentication headers:

- `X-UltraCache-Cookie-Control-Body-SHA256`: lowercase body SHA256.
- `X-UltraCache-Cookie-Control-Signature`: `v1=` plus HMAC-SHA256 of the following.

```text
ultracache-cookie-control-v1
response
<HTTP status number>
<requestId>
<lowercase response body SHA256>
```

The native client authenticates the declared digest before reading any body,
streams authenticated bytes to a private temporary file, checks the actual
digest, then decodes JSON. An unsigned origin cannot make the root worker buffer
an arbitrary body. There is no new arbitrary output-size or work-duration cap.

## Native transaction and recovery

Status is read-only preflight. Persist the operation identity, base/target digest
and desired snapshot in the existing private native journal before prepare.
Prepare validates/stages, native VCL compiles, the application commits through
its existing settings transaction, native VCL activates, and the affected site
cache is invalidated after both sides apply. Native settings are then committed.
No unrelated purge, media cleanup, hidden warm or website scan is introduced.

Ordinary inventory reads do not contact WordPress. Explicit cookie Save resyncs
the selected connected site(s), even if the local files look unchanged; archive
restore does the same. Actual signed base/target differences identify app drift
without purging pages for description changes.

Changing endpoints clears the old managed snapshot then applies the new one.
These URLs may reach the same WordPress. Defer preparing the new application
operation until the clear has committed; refresh status/base digest then stage
the new policy. Recovery skips deferred operations that never mutated anything.
Rollback executes in reverse order and covers a lost commit response, not just
operations whose response the native worker received.

Rollback success includes the actual active digest and `rollbackState`:

- `restored`: the previous policy and required local invalidation really finished;
  the active digest must equal the recorded base.
- `not-applied`: this transaction never applied; its stage was canceled without
  overwriting a policy that another writer may have changed.
- `superseded`: a newer writer owns the active state and is preserved.

Only the latter two allow a digest different from the base. Record that actual
disposition. The original job still fails for its original cause; preserving a
newer policy is not a claim that the old application policy was restored. A real
failed rollback/local purge retains the durable identity for retry. Cancellation
before prepare and replay of a closed abort must not resurrect old transactions.

Disabling the explicit connection clears the managed app snapshot before saving
the disconnection. A failure retains the previous native choices with its actual
cause. Removing Varnish itself does not depend on a reachable WordPress site:
the app retains its last valid policy and works independently; its authenticated
admin reset can clear a managed snapshot. A retained native panel may support an
app-only settings transaction while the Varnish service is removed.
