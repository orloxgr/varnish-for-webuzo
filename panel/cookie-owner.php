<?php if (!defined('SOFTACULOUS') || !isset($escape, $csrf) || !empty($isAdmin)) { http_response_code(403); exit; } ?>
<style><?php require __DIR__ . '/style.css'; ?></style>
<section id="wvw" data-token="<?= $escape($csrf) ?>">
  <h2>Cookie cache policies</h2>
  <p>Choose how cookies affect shared HTML for your own sites. Your choices override the hosting defaults; application privacy and login protection still apply.</p>
  <div id="wvw-cookie-admin"></div>
</section>
<script><?php require __DIR__ . '/cookie-admin.js'; ?></script>
<script>
(() => {
  const root = document.getElementById('wvw');
  const request = async (action, values = {}) => {
    const body = new URLSearchParams({token: root.dataset.token, payload: JSON.stringify({action, ...values})});
    const response = await fetch(location.href, {method:'POST', credentials:'same-origin', body});
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || 'Cookie policies could not be loaded.');
    return data;
  };
  window.WebuzoCookiePolicies.mount(document.getElementById('wvw-cookie-admin'), request);
})();
</script>
