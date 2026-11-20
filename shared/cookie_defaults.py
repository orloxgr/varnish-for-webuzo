"""Concrete editorial defaults, independent of downloaded recognition labels.

Name/description inferences are estimates, never provider certification. Values
are not read here and categories never become executable rules.
"""
import copy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

NAME = re.compile(r'[^\x00-\x1f\x7f;="{}]+')
REFERENCES = {
 'cloudflare':'https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/',
 'wordpress':'https://developer.wordpress.org/advanced-administration/wordpress/cookies/',
 'shopify':'https://www.shopify.com/legal/cookies',
 'hubspot':'https://knowledge.hubspot.com/privacy-and-consent/what-cookies-does-hubspot-set-in-a-visitor-s-browser',
 'magento':'https://experienceleague.adobe.com/en/docs/commerce-admin/start/compliance/privacy/compliance-cookie-law',
}
SHARED = {
 'Cloudflare':'__cfduid __cfruid __cf_bm cf_chl_2 _cfuvid cf_clearance __cfseq',
 'Hubspot':'__hstc hubspotutk __hssc __hssrc',
 'Shopify':'_landing_page _orig_referrer _s _shopify_fs _shopify_s _shopify_sa_t _shopify_uniq _shopify_visit _shopify_y _y tracked_start_checkout ki_r ki_t _shopify_d shop_analytics _shopify_sa_p _shopify_ga',
 'WordPress':'wordpress_test_cookie',
 'Magento':'mage-translation-file-version mage-translation-storage searchReport-log',
 'Hotjar':'_hjIncludedInSample',
 'Sharpspring':'__ss',
 'Adobe Advertising':'everest_session_v2',
 'Braze':'ab.storage.userId. ab.storage.sessionId.',
 'Salesforce':'pctrk',
 'Media.net':'mnet_session_depth',
 'Dotomi':'DotomiSession_',
 'Yandex.Metrica':'yabs-sid',
 'Parse.ly':'_parsely_session',
 'Marfeel':'compass_sid',
 'RD Station':'_rd_wa_first_session _sp_wa_first_session',
 'Visual Website Optimizer':'_vis_opt_test_cookie',
}
PRIVATE = {
 'Shopify':'_ab _secure_session_id Cart cart_sig cart_ts checkout_token Secret Secure_customer_sig secure_customer_sig storefront_digest _shopify_u _Brochure_session shopify_pay_redirect checkout_session_token checkout_session_lookup cart_ver _customer_account_shop_sessions _secure_account_session_id _storefront_u remember_me shopify_pay shop_pay_accelerated checkout_prefill checkout_queue_token checkout_worker_session checkout_session_token_ identity-state identity-state- identity_customer_account_number card_update_verification_id customer_account_new_login customer_account_preview customer_payment_method customer_shop_pay_agreement pay_update_intent_id profile_preview_token login_with_shop_finalize preview_theme shopify-editor-unconfirmed-settings _shopify_essential _shopify_essential_',
 'Magento':'form_key frontend guest-view persistent_shopping_cart section_data_ids private_content_version external_no_cache',
 'Azure / Microsoft':'buid esctx fpc stsservicecookie __AntiXsrfToken .ASPXANONYMOUS .ASPXAUTH nSGt- RpsContextCookie ASPSESSIO .AspNetCore.Mvc.CookieTempDataProvider x-ms-cpim-admin x-ms-cpim-trans x-ms-cpim-sso x-ms-cpim-cache x-ms-cpim-csrf x-ms-cpim-ctx x-ms-cpim-rp x-ms-cpim-rc',
 'CookieYes':'cookieyes_privacy_policy_generator_session cookieyes_session',
}


def valid_name(name):
    # Literal PCRE escaping below handles slash/colon/brackets/Unicode. Quotes,
    # braces and Cookie delimiters cannot become VCL source or a second pair.
    return isinstance(name,str) and name == name.strip() and bool(NAME.fullmatch(name))


def infer(name, provider, description, reviewed=None):
    sources=[REFERENCES[provider.lower()]] if provider.lower() in REFERENCES else []
    def decision(action, role, reason, confidence='inferred'):
        return dict(proposal=action,htmlEffect=role,confidence=confidence,
            reason=name+' ('+provider+'): '+reason,sources=sources,
            method='literal-name-and-description editorial assessment; not a site-specific execution trace')
    if reviewed:return dict(reviewed,method='existing-reviewed-execution-policy')
    if provider.lower()=='woocommerce' and name=='store_notice':
        base='https://github.com/woocommerce/woocommerce/blob/89153b67a27a0bcbf983d4ffd020a86f90e493ec/'
        result=decision('shared','client-side-notice-dismissal',
            'WooCommerce 11.3.1 emits the same initially hidden store notice without reading this cookie. Native woocommerce.js reads store_notice + noticeId to show, hide and dismiss it in the browser. Custom server-side notice integrations can override this default.',
            'source-reviewed')
        result['sources']=[base+'plugins/woocommerce/includes/wc-template-functions.php',
            base+'plugins/woocommerce/client/legacy/js/frontend/woocommerce.js']
        result['method']='WooCommerce 11.3.1 pinned source review; native/browser acceptance pending'
        return result
    if name in ('GA_OPT_OUT','dnt','eu_cn') or provider=='Joomla!' and name in ('componentType','componentStyle') or provider=='Facebook' and name=='locale':
        return decision('variant','public-preference','This is a consent, locale or template preference, not an account credential. Separate public representations by value without bypassing the cache.')
    for group,action,role,reason in (
      (PRIVATE,'private','personal-or-security','Account, checkout, private session or CSRF state: matching requests go to the application.'),
      (SHARED,'shared','no-initial-html-variation','Measurement, client/edge verification or capability state does not select initial origin HTML. Keep the original cookie and provider/consent checks.')):
        if any(provider.lower()==p.lower() and name in names.split() for p,names in group.items()):
            return decision(action,role,reason)
    text=description.lower(); lower=name.lower()
    if re.search(r'consent|cookie preference|cookie polic|cookie banner|cookies.*accept|accept.*cookies|opt[ -]?out|opt[ -]?in|privacy (setting|preference)',text) or re.search(r'consent|cmplz_|cookieyes|cookie_notice|optanon|euconsent|gdpr',lower):
        return decision('variant','consent-variant','Consent can select scripts/HTML. Keep separate public representations per consent value; this rule never grants consent or issues a cookie.')
    if re.search(r'authenticat|logged[ -]in|log[ -]?in|password|csrf|xsrf|shopping cart|basket|payment session|customer session|account session|secure session|access token|user credentials',text) or re.search(r'(^|[_.:-])(auth|csrf|xsrf|jwt|sessionid|phpsessid)([_.:-]|$)|^a0_users:sess|^wordpress_sec_|^wp-postpass',lower):
        return decision('private','personal-or-security','The described role carries account, session, cart or request-security state; do not share a full response across visitors.')
    if re.search(r'currency|language|locali[sz]|country|timezone|time zone|load balanc|server affinity|sticky session|backend.*server|routing.*server',text) or re.search(r'(^|[_.-])(lang|locale|currency)([_.-]|$)|^aws(alb|elb)|^arraffinity|^aslbsa|^applicationgatewayaffinity|^__cflb$',lower):
        return decision('variant','public-representation','Language, region, currency or routing preference can select public HTML. Include its value in the cache key, without forcing bypass.')
    if re.search(r'personali[sz]|recommendation|recently viewed|wishlist|wish list|a/b test|ab test|split.test|experiment|test variant|user preference|visitor preference|previously.*viewed',text):
        return decision('variant','personalization-variant','Preference/history/experiment state can change content. Separate objects by its value; application private/no-store decisions still win.')
    if re.search(r'analytics|analytical|statistic|tracking|track |tracks |track\b.*(visitor|user|page|click|conversion)|measure|advertis|marketing|attribut|campaign|conversion|retarget|audience|pixel|ad exchange|ad serving|ad delivery|programmatic|bidding|synchroni[sz]|cookie sync|cross[ -]site|cross[ -]domain.*identif|unique.*identif|identif.*unique|session replay|heatmap|performance monitor|error monitor|page.?view|referral|referrer',text):
        return decision('shared','measurement-or-client-service','The stated role is measurement, attribution or client service delivery rather than initial server HTML. Exclude its value from variation; forward the original cookie unchanged.')
    if re.search(r'session identif|session id|session token|session state|session management|session cookie|maintain.*session|preserv.*session|manag.*session',text) or re.search(r'(^|[_.:-])(session|sess)([_.:-]|$)',lower):
        return decision('private','application-session','Application session state has no public-page contract here. Matching requests go to the application; a verified client-only integration can override this choice.')
    return decision('variant','application-dependent-variant','The description does not establish identical initial HTML. Our concrete default separates objects per value (including absence), without forcing PASS or ignoring a potentially meaningful value.','inferred-low')


@lru_cache(maxsize=1)
def bundle():
    data=json.loads(Path(__file__).with_name('cookie-assessments.json').read_text(encoding='utf-8'))
    rules=[]
    for identity,row in data['records'].items():
        action=row['proposal']
        literal=row.get('matchValue',row['name'])
        if action not in ('shared','variant','private') or not valid_name(literal):
            raise ValueError('Bundled cookie defaults need concrete actions and safe literal names')
        rules.append(dict(id='bundled:'+identity,match=dict(kind='prefix' if row.get('wildcard') else 'exact',
            value=literal.removesuffix('*') if row.get('wildcard') else literal),description=row['description'],action=action))
    from cookie_catalogue import load_catalogue
    for row in load_catalogue()['policies']:
        action='private' if row['consumers']['varnishPrivate'] else 'shared'
        rules.append(dict(id='bundled:policy:'+row['id'],match=row['match'],description=row.get('description',''),action=action))
    # Duplicate provider names use the editorial common decision from the build.
    # Reviewed catalogue matches remain authoritative over inferred duplicates.
    unique={}
    for rule in rules:unique[(rule['match']['kind'],rule['match']['value'])]=rule
    return dict(schemaVersion=1,rules=list(unique.values())),data


def defaults():
    return copy.deepcopy(bundle()[0])


def fingerprint():
    """Execution identity, unaffected by an editorial text/version-only edit."""
    projection=sorted((row['match']['kind'],row['match']['value'],row['action']) for row in bundle()[0]['rules'])
    return hashlib.sha256(json.dumps(projection,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()


def assessment(match):
    rule=rule_for(match)
    return rule['action'] if rule else 'variant'


def rule_for(match):
    return _assessment(match['kind'],match['value'])


@lru_cache(maxsize=None)
def _assessment(kind,value):
    match={'kind':kind,'value':value}
    rows=[r for r in bundle()[0]['rules'] if r['match']==match or
          r['match']['kind']=='prefix' and match['value'].startswith(r['match']['value'])]
    rows.sort(key=lambda r:(r['match']['kind']!='exact',-len(r['match']['value'].encode('utf-8')),r['id']))
    return rows[0] if rows else None
