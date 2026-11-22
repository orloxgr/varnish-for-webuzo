"""Registration epoch follows its actual native registry lifetime."""
import shutil
import time
import unittest
from test_cookie_delivery import proxy
from test_cold_public_selection import Application
from test_public_selection_runtime import control,WP_POLICY
EPOCH='X-UltraCache-VCL-Public-Selection-Epoch'
POLICY='X-UltraCache-VCL-Public-Selection-WordPress-Policy'

@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required')
class PublicationEpoch(unittest.TestCase):
    def test_new_manager_with_same_module_has_new_empty_registry_epoch(self):
        with proxy('ultracache',Application()) as first:
            status,fields,_=control(first,enabled=True,names='')
            self.assertEqual(status,200);previous=fields[EPOCH]
            self.assertRegex(previous,r'^[a-f0-9]{64}$');self.assertEqual(fields[POLICY],WP_POLICY)
        with proxy('ultracache',Application()) as second:
            status,fields,_=control(second)
            self.assertEqual(status,200);self.assertNotIn(POLICY,fields)
            self.assertRegex(fields[EPOCH],r'^[a-f0-9]{64}$')
            self.assertNotEqual(fields[EPOCH],previous)
    def test_child_restart_in_same_manager_changes_epoch_and_empties_registry(self):
        with proxy('ultracache',Application(),management=True) as get:
            status,fields,_=control(get,enabled=True,names='')
            self.assertEqual(status,200);epoch=fields[EPOCH]
            get.adm('stop');get.adm('start')
            deadline=time.monotonic()+10
            while True:
                try:
                    status,fields,_=control(get)
                    if status==200:break
                except (OSError,ConnectionError):pass
                if time.monotonic()>=deadline:self.fail('Owned restarted child did not become ready')
                time.sleep(.05)
            self.assertNotEqual(fields[EPOCH],epoch);self.assertNotIn(POLICY,fields)

    def test_overlapping_vcl_reload_preserves_registry_and_epoch(self):
        with proxy('ultracache',Application(),management=True) as get:
            status,fields,_=control(get,enabled=True,names='')
            self.assertEqual(status,200);epoch=fields[EPOCH]
            get.activate('overlapping',get.source)
            status,fields,_=control(get)
            self.assertEqual((status,fields[EPOCH],fields[POLICY]),(200,epoch,WP_POLICY))

if __name__=='__main__':unittest.main()
