<?php if (!defined('SOFTACULOUS') || !isset($escape, $csrf)) { http_response_code(403); exit; } ?>
<style><?php require __DIR__ . '/style.css'; ?></style>
<section id="wvw" data-token="<?= $escape($csrf) ?>">
  <h2>Varnish Cache</h2>
  <p>Serve images, styles and scripts with Nginx. Cache public pages with Varnish and send private requests to WordPress.</p>
  <div id="wvw-error" role="alert" hidden></div><div id="wvw-notice" role="status" hidden></div>
  <div class="wvw-toolbar"><strong id="wvw-status">Checking service…</strong><button type="button" id="wvw-install" hidden>Install &amp; set up Varnish</button><button type="button" id="wvw-start" hidden>Start Varnish</button><button type="button" id="wvw-refresh">Refresh sites</button></div>
  <section class="wvw-card" id="wvw-server" hidden>
    <h3>Server cache</h3>
    <div class="wvw-toolbar"><label for="wvw-memory">Cache size (MiB)</label><input type="number" id="wvw-memory" min="1" step="1"><button type="button" id="wvw-resize">Apply cache size</button><button type="button" id="wvw-usage">Show memory usage</button></div>
    <p>The cache size is shared by all enabled sites. Changing it restarts Varnish and clears the shared cache. Total service memory also includes processing and connection overhead.</p>
    <div id="wvw-usage-result" role="status" hidden></div>
  </section>
  <p>New sites start with Varnish disabled. Enable each site below. Logged-in visitors, cookies, query strings and write requests bypass the cache.</p>
  <div class="wvw-scroll"><table><thead><tr><th>Site / Account</th><th>Varnish</th><th>Maximum cache lifetime</th><th>Additional bypass paths</th><th>Actions</th></tr></thead><tbody id="wvw-sites"></tbody></table></div>
  <section id="wvw-site-settings"><h3>Site VCL and connection details</h3><div id="wvw-details"></div></section>
  <p><button type="button" id="wvw-remove" hidden>Remove Varnish setup</button></p>
</section>
<script><?php require __DIR__ . '/app.js'; ?></script>
