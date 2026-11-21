"""Explicit per-site shared-cache override; no settings migration or old TTL cap."""
DEFAULT_TTL = 86400
COOKIE_RULE_REVISION = 1


def settings(site):
    enabled = site.get('aggressive', False)
    ttl = site.get('aggressive_ttl', DEFAULT_TTL)
    if type(enabled) is not bool:
        raise ValueError('Aggressive caching must be a checkbox value')
    if type(ttl) is not int or ttl <= 0:
        raise ValueError('Aggressive cache duration must be a positive number of seconds')
    return dict(aggressive=enabled, aggressive_ttl=ttl)


def cookie_rules_changed(before, after):
    """Invalidate old aggressive replicas once when its cookie override retires."""
    return settings(before)['aggressive'] and before.get('cookie_rules_revision',0) != after.get('cookie_rules_revision',0)
