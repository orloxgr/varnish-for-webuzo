=== Varnish Cache for Webuzo ===
Contributors: orloxgr
Tags: cache, varnish, webuzo
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Clear this site's Varnish cache from WordPress.

== Description ==

Clear cached pages from Tools → Varnish Cache after changing your website. Cache clearing is manual and affects only the site provisioned by your hosting provider, including its aliases.

The hosting provider must install Varnish for Webuzo and enable your site. Its separate site credential is stored privately under the hosting account's home. PHP POSIX and cURL with Unix socket support are required. No panel password or general API key is used. Requests stay on the server using a protected local Unix socket.

== Installation ==

1. Ask your hosting provider to enable Varnish for your site in Webuzo.
2. Install and activate this WordPress ZIP.
3. Open Tools → Varnish Cache and click Clear this site's cache.

This is an independent third-party integration, not affiliated with, endorsed, sponsored, or supported by Webuzo or Softaculous.
