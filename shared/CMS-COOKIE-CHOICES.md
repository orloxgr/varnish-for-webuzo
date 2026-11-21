# CMS cookie choices

The CMS descriptor selects private routes and actions. Cookie classification
uses the same visible, scoped resolver as the cookie editor and connected
application snapshots. A CMS-specific cookie check must not override a selected
Shared HTML or Public variant action before that resolver runs.

Bundle `2026.11.21.1` adds ordinary Private defaults in both profiles:

| Match | Provider evidence |
| --- | --- |
| `SSESS*`, `SESS*` | [Drupal 11.2.0 session names](https://github.com/drupal/drupal/blob/11.2.0/core/lib/Drupal/Core/Session/SessionConfiguration.php) |
| `PrestaShop-*` | [PrestaShop 9.0.0 combined encrypted cookie](https://github.com/PrestaShop/PrestaShop/blob/9.0.0/classes/Cookie.php) |
| `joomla_user_state` | [Joomla 5.4.0 login marker and logout deletion](https://github.com/joomla/joomla-cms/blob/5.4.0/plugins/user/joomla/src/Extension/Joomla.php) |
| `joomla_remember_me_*` | [Joomla 5.4.0 remembered authentication](https://github.com/joomla/joomla-cms/blob/5.4.0/plugins/system/remember/src/Extension/Remember.php) |

These defaults also apply to real response cookie fields. They remain editable
independently in Basic and UltraCache; reset restores Private. They do not issue
cookies. An explicit Shared choice does not change the separate origin privacy,
HTTP authentication or private route/action decisions.

The visible literal prefixes are deliberately the ordinary editor match type.
They replace the old hidden, CMS-scoped hex-name checks. Joomla's ordinary login
marker is set to `logged_in` and deleted on logout; the visible rule is Private
for the cookie name, including any nonstandard values. Operators can select
another action explicitly instead of having a second value classifier.

Both structural profile fingerprints change. Normal apply synchronizes a
connected application's materialized policy and invalidates affected site
caches. Existing saved choices keep precedence; an unchanged repeated apply
keeps its existing identity.

Qualification uses isolated Varnish 9.1 instances and real HTTP origins with CMS
descriptors. The published baselines return PASS for all six CMS/profile Shared
cases per adapter. The candidate reuses Shared HTML, stores separate reusable
Public variants, forwards original cookies, retains explicit/default Private
and keeps private CMS routes on PASS. Additional checks cover independent
profile overrides, reset, signed materialization and the frozen prior profile
fingerprints. These are native protocol fixtures plus pinned provider source
review, not installations of the three complete CMS applications. They do not
establish production or WordPress warm-up acceptance.
