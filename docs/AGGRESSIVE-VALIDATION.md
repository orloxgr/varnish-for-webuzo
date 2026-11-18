# Aggressive HTML and known CMS validation

Development acceptance for the opt-in Basic/UltraCache extension. No customer
server was changed by these checks and no public release has been published.

## 0.9.1 search-only directory correction

A read-only production diagnostic found that the hosting UID could traverse
the normal 0711 `/home` but the literal configuration reader incorrectly opened
each ancestor O_RDONLY, which also required directory-list permission. This
caused `joomla-session-unavailable` before any database query. Ancestors now use
O_PATH with O_DIRECTORY and O_NOFOLLOW; the final regular file still requires
read permission. No hosting permissions or application files are changed.

With the corrected reader loaded only in the diagnostic process's memory, the
same production hosting UID successfully read session/database metadata and
executed the read-only session lookup. The CMS helper source identity now
includes discovery and route dependencies, so native plugin activation reloads
the worker after these modules change.

The correction passed 20 native CMS route/metadata/activation methods, five
package checks, and the generated systemd helper running its hosting UID below
a search-only 0711 ancestor. The regression still rejects symbolic links and
enforces final-file read and directory search permissions. Hestia copied the
identical shared reader and passed 24 focused methods, including an actual
helper restart when either discovery or route dependencies change. The VCL
and native module remain unchanged from the 0.9.0 policy validation below.

## Verified native behavior

On the disposable Webuzo lab, Varnish 9.1 compiled the ABI-matching cookie
module and both generated product profiles. The native token/body suite passed:

- Public Joomla parent: fetching visitor MISS with its original token/cookie;
  second visitor HIT with its own token/cookie; returning first visitor HIT
  with its own token and no foreign Set-Cookie replay.
- The same assertions with a gzipped origin body and multiple complete cookie
  fields larger than the old diagnostic frame.
- Token-provider failure returns the original origin HTML with a specific PASS
  reason, rather than an unresolved template or another visitor's token.
- Actual token-bearing forms remain private. Ordinary newsletter forms,
  comments, JavaScript examples and textarea examples remain cacheable.
- Large HTML with a token at the end is inspected without a body-size cutoff.
- Generic request restart can still land on an existing HIT; only a failed
  private token preparation uses the token retry fallback.
- Native discovery covers Magento's pub document root and real administrator
  frontName, plus PrestaShop's renamed admin entrypoint. Static PHP reads do not
  execute customer code. Configured query IDs are scoped to their public base.
- A PrestaShop combined customer/cart cookie cannot seed shared HTML or reuse
  an anonymous object. Anonymous requests without that private carrier still
  MISS then HIT. Both presets passed the same common case.

The full Webuzo Python run executed 325 methods. It found an overly broad
request-restart fallback, which was corrected and rechecked in both profiles.
A separate native child-load failure was rerun successfully after native module
rebuild activity stopped. The final focused run passed all 24 methods covering
the changed native lifecycle, tokens, CMS metadata/discovery, REST authentication
and effective cookie-editor defaults. Five package/version tests also passed,
including shipping the native header with normalized line endings.

The Hestia worker additionally proved the complete shared flow with actual PHP
sessions, MariaDB, the root-owned broker and native Varnish ESI. The original
full-page URL was fetched only once; separate visitors retained their own real
application-generated session cookies and form tokens. This is application
component work on a parent HIT, not a claim of zero PHP execution.

## Final cross-panel acceptance

The strict comparison verified 36 identical common source files and 115 identical
successful native scenario results in Webuzo and Hestia. The source set includes
the native module, both presets' common VCL, CMS discovery, metadata, session
resolution and the scenario runner. Hestia also passed 36 focused methods and
its reversible native installer check. Its actual PHP UNIX-origin test proved
that the real Joomla component returns request-owned cookies/tokens through the
root broker; neither the origin credential nor socket is passed to the hosting
UID worker.

## Installed Webuzo acceptance

After the official licensing form and native license refresh restored panel
access, version 0.9.0 was uploaded and activated through Webuzo's native plugin
ZIP handler on the disposable VM. No vendor licensing files were patched.

The actual installed panel showed aggressive caching initially OFF, the
discovered CMS bases, and a default aggressive duration of 86400 seconds.
Saving 90000 seconds persisted across a browser reload and appeared unchanged
in the active native VCL. Both Basic and UltraCache were saved through the UI.
The service remained running and no transaction journal remained pending.

A disposable PHP endpoint created a genuine PHP session and returned public
HTML together with private/no-store headers. Through the installed Nginx and
Varnish route, both presets produced MISS, HIT, HIT for three requests with
different tracking URLs and generic PHP session cookies. The bodies matched;
the origin visitor's cookie was not replayed to subsequent visitors. The
original browser Cache-Control policy remained intact.

The temporary endpoint was removed and the lab site's original UltraCache,
aggressive-OFF and 86400-second settings were restored. No live deployment,
Git push or public release was performed.
