"""Reuse identical cookie execution projections within one reconciliation stage."""
import json
import cookie_admin


def projections():
    # This cache belongs to the calling operation, never a persisted inventory
    # or a timer. Changed input has a new key, including in-place edits.
    cached = {}

    def project(central, site,profile='basic'):
        key = json.dumps([central, site,profile], sort_keys=True, separators=(',', ':'))
        if key not in cached:
            cached[key] = tuple(cookie_admin.executable(central, site,profile))
        return cached[key]

    return project
