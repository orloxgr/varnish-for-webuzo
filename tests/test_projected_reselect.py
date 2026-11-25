"""Projected public lookup and verified conflict recovery must use the same key.

Actual ephemeral native Varnish, declared mock application; not WP/live acceptance.
"""
import json
import shutil
import unittest

from test_cookie_delivery import proxy
from test_cms_cookie_choices import cache
from test_cold_public_selection import choices
from test_public_selection_runtime import control
from test_projected_source_runtime import ProjectedApplication
from test_publication_reselect import Publications


class SourcePublications(Publications):
    def __call__(self, path, headers):
        result = super().__call__(path, headers)
        if headers.get('X-UltraCache-Delivery-Public-Source-Role') != 'parent-v1':
            return result
        body, fields = result
        value = json.loads(body)
        selected = value['selectedPublic']
        selected.pop('renderedFragments')
        selected.pop('cookieUpdates')
        selected['publicSource'] = dict(version=1, role='parent-v1')
        fields = [(name, val) for name, val in fields if name != 'X-UltraCache-Delivery-Outcome']
        fields += [('X-UltraCache-Delivery-Public-Source-Version', '1'),
                   ('X-UltraCache-Delivery-Public-Source-Outcome', 'captured')]
        return json.dumps(value), fields


class ProjectedPublications(ProjectedApplication):
    def __init__(self):
        super().__init__()
        self.normal = SourcePublications()

    def __call__(self, path, headers):
        # Existing verified reselection has no resolver/pure-source phase.
        if (headers.get('X-UltraCache-Delivery-Phase') == 'public-select'
                and not headers.get('X-UltraCache-Delivery-Public-Source-Projection')
                and not headers.get('X-UltraCache-Delivery-Public-Source-Role')):
            return self.normal(path, headers)
        return super().__call__(path, headers)


@unittest.skipUnless(shutil.which('varnishd'), 'Actual native engine required')
class ProjectedReselect(unittest.TestCase):
    def test_reselection_leaves_next_visit_on_ordinary_projected_key(self):
        app = ProjectedPublications()
        policy = choices(('brandCurrency', 'variant'), ('cmp_language', 'variant'),
                         ('optional', 'variant'), ('cart', 'shared'))
        with proxy('ultracache', app, policies=policy) as get:
            status, _, _ = control(get, enabled=True, names='brandCurrency', extra={
                'X-UltraCache-Public-Selection-Public-Source-Version': '1',
                'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1'})
            self.assertEqual(status, 200)
            cookie = 'brandCurrency=EUR; cmp_language=el; cart=A'
            extra = {'Accept': 'text/html', 'X-Test-Visitor': 'A'}
            first = get('/projected-reselection', cookie, extra)
            self.assertEqual((first[0], cache(first[1])), (200, 'MISS'))
            self.assertIn('A[', first[2])
            app.normal.generations['/projected-reselection'] = 'B'
            before = len(app.normal.observed)
            recovered = get('/projected-reselection', cookie, extra)
            self.assertEqual(recovered[0], 200)
            self.assertIn('B[', recovered[2])
            self.assertEqual([r[1] for r in app.normal.observed[before:]], ['prepare', 'public-select'])
            before = len(app.normal.observed)
            following = get('/projected-reselection', cookie, extra)
            self.assertEqual((following[0], cache(following[1])), (200, 'HIT'))
            self.assertIn('B[', following[2])
            self.assertEqual([r[1] for r in app.normal.observed[before:]], ['prepare'],
                             'projected-reselect-next-request: must not repeat conflict/reselection or resolve the same tuple again')


if __name__ == '__main__':
    unittest.main()
