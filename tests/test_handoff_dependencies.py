"""Native headers follow the installed engine and cannot replace its package."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'shared')]
import repository
import native_build


class HandoffDependencies(unittest.TestCase):
    def test_matching_headers_and_toolchain_require_no_package_work(self):
        with patch.object(repository.native,'run',return_value='9.1 installed') as command,\
             patch.object(repository.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'9.1 installed','')),\
             patch.object(repository.shutil,'which',return_value='/usr/bin/tool'),\
             patch.object(native_build,'build',return_value=Path('/native/module.so')) as build:
            self.assertEqual(repository.ensure_cookie_handoff(),Path('/native/module.so'))
        build.assert_called_once()
        self.assertEqual(command.call_args_list[0].args,('dpkg-query','-W','-f=${Version} ${db:Status-Status}','varnish'))
        self.assertEqual(command.call_count,1)

    def fixture(self,preview):
        calls=[]
        def command(*args):
            calls.append(args)
            if args[0]=='dpkg-query':return '9.1 installed'
            if args[:2]==('apt-get','-s'):return preview
            return ''
        self.enterContext(patch.object(repository.native,'run',side_effect=command))
        self.enterContext(patch.object(repository.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','missing')))
        self.enterContext(patch.object(repository.shutil,'which',return_value=None))
        self.enterContext(patch.object(repository,'release',return_value='noble'))
        self.enterContext(patch.object(repository,'architecture',return_value='amd64'))
        self.enterContext(patch.object(repository,'existing_source',return_value=True))
        self.enterContext(patch.object(Path,'exists',return_value=False))
        return calls

    def test_dependencies_pin_the_engine_and_do_not_restart_it(self):
        calls=self.fixture('Inst varnish-dev (9.1)\n')
        with patch.object(native_build,'build') as build:repository.ensure_cookie_handoff()
        build.assert_called_once()
        self.assertIn(('env','DEBIAN_FRONTEND=noninteractive','NEEDRESTART_MODE=l','apt-get','install','-y','--no-remove',
            'varnish=9.1','varnish-dev=9.1','build-essential','pkg-config'),calls)
        self.assertFalse(any('systemctl' in call for call in calls))

    def test_engine_replacement_or_removal_is_refused_before_install_or_build(self):
        for preview in ('Inst varnish [9.1] (10.0)\n','Inst varnish:amd64 [9.1] (10.0)\n','Remv other-service [1.0]\n'):
            with self.subTest(preview=preview):
                # Each subcase gets an independent fixture and mock lifetime.
                with patch.object(repository.native,'run') as command,\
                     patch.object(repository.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','missing')),\
                     patch.object(repository.shutil,'which',return_value=None),\
                     patch.object(repository,'release',return_value='noble'),\
                     patch.object(repository,'architecture',return_value='amd64'),\
                     patch.object(repository,'existing_source',return_value=True),\
                     patch.object(Path,'exists',return_value=False),patch.object(native_build,'build') as build:
                    command.side_effect=lambda *args:'9.1 installed' if args[0]=='dpkg-query' else preview if args[:2]==('apt-get','-s') else ''
                    with self.assertRaisesRegex(ValueError,'will not replace'):repository.ensure_cookie_handoff()
                    build.assert_not_called()
                    self.assertFalse(any(call.args[0]=='env' for call in command.call_args_list))


if __name__=='__main__':unittest.main()
