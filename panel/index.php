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
    <p id="wvw-timeouts"></p>
    <div class="wvw-toolbar"><label for="wvw-control-port">Local HTTP connection port</label><input type="number" id="wvw-control-port" min="1" max="1023" step="1" value="82"><button type="button" id="wvw-save-connection">Save connection port</button></div>
    <p>Application purge requests use this loopback-only port and a separate token for each site. Show connection information in the site's row for the endpoint and authentication values.</p>
  </section>
  <section class="wvw-card" id="wvw-profiles" hidden>
    <h3>VCL profiles</h3>
    <div class="wvw-toolbar"><label for="wvw-default-profile">Default for new sites</label><select id="wvw-default-profile"></select><button type="button" id="wvw-save-default">Save default</button></div>
    <p>New sites receive this profile when discovered and start with Varnish disabled. Existing sites keep their assigned profile. Basic is the initial default.</p>
    <details><summary>Central profile VCL templates</summary>
      <label for="wvw-edit-profile">Profile</label><select id="wvw-edit-profile"></select>
      <p id="wvw-profile-description"></p>
      <details><summary>View built-in VCL</summary><pre id="wvw-profile-source"></pre></details>
      <p>Add central rules below to extend this profile. They apply to all sites assigned to this profile, including new sites. Per-site additions remain separate.</p>
      <label for="wvw-profile-recv">Additional request VCL</label><textarea id="wvw-profile-recv" class="wvw-vcl"></textarea>
      <label for="wvw-profile-backend">Additional response VCL</label><textarea id="wvw-profile-backend" class="wvw-vcl"></textarea>
      <p id="wvw-profile-targets"></p><button type="button" id="wvw-save-profile" class="wvw-primary">Validate &amp; Apply profile rules</button>
    </details>
  </section>
  <p>Choose a profile and enable Varnish for each site below. Open VCL &amp; connection in that site's row to view its profile rules, add site-specific rules or show its connection information.</p>
  <div class="wvw-scroll"><table><thead><tr><th>Site / Account</th><th>Profile</th><th>Varnish</th><th>Maximum cache lifetime</th><th>Additional bypass paths</th><th>Actions</th></tr></thead><tbody id="wvw-sites"></tbody></table></div>
  <p><button type="button" id="wvw-remove" hidden>Remove Varnish setup</button></p>
</section>
<script><?php require __DIR__ . '/app.js'; ?></script>
