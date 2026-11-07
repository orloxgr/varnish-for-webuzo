"""Application cookie exclusions; additional owner rules can only add bypasses."""
import re

# WordPress private state, PHP sessions and common personalized Woo extensions.
# A persistent session may hold notices/customer data without browser-session
# cart markers. Both groups bypass shared HTML unless UltraCache approves ESI.
PRIVATE = ('wordpress_logged_in_*', 'wordpress_sec_*', 'wp-postpass_*', 'comment_author_*',
           'PHPSESSID', 'woocommerce_recently_viewed', 'yith_wcwl_session_*', 'yith_woocompare_*')
CART = ('woocommerce_items_in_cart', 'woocommerce_cart_hash')
SESSION = ('wp_woocommerce_session_*',)
RULE = re.compile(r"[!#$%&'+.^_`|~0-9A-Za-z-]+\*?")


def normalize(value):
    if isinstance(value, str):
        value = value.splitlines()
    if not isinstance(value, list):
        raise ValueError('Use cookie names or trailing-star prefixes')
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError('Cookie rules must be names, one per line')
        item = item.strip()
        if not item:
            continue
        if not RULE.fullmatch(item):
            raise ValueError('Use valid HTTP cookie names; only a trailing * is interpreted as a prefix wildcard')
        if item not in result:
            result.append(item)
    return result


def pattern(rules):
    names = []
    for rule in normalize(list(rules)):
        name = re.escape(rule.removesuffix('*'))
        if rule.endswith('*'):
            name += '[^=;[:blank:]]*'
        names.append(name)
    if not names:
        raise ValueError('An empty cookie rule list has no match pattern')
    return '(^|;[[:blank:]]*)(' + '|'.join(names) + ')='


def vcl_pattern(rules):
    # Native long strings preserve PCRE escapes. Cookie names cannot contain
    # quotes/braces, so they cannot terminate this generated VCL literal.
    return '{"' + pattern(rules) + '"}'
