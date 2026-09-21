"""Carrier lifecycle checks with a foreign enclave present and the real supervisor."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "run-worker-enclave.sh"
MOCK = '''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root = Path(os.environ['CARRIER_TEST_ROOT'])
args = sys.argv[1:]
if Path(sys.argv[0]).name == 'nitro-cli':
    if args[0] == 'run-enclave':
        name = args[args.index('--enclave-name')+1]
        item = dict(EnclaveID='owned', EnclaveCID=99, EnclaveName=name, State='RUNNING')
        (root/'owned.json').write_text(json.dumps(item))
        print(json.dumps(item))
    elif args[0] == 'describe-enclaves':
        items = [dict(EnclaveID='foreign', EnclaveCID=16, EnclaveName='someone-else', State='RUNNING')]
        if (root/'owned.json').exists(): items.append(json.loads((root/'owned.json').read_text()))
        print(json.dumps(items))
    elif args[0] == 'terminate-enclave':
        assert args[-1] == 'owned', 'terminated another enclave'
        (root/'terminated').touch()
        if not (root/'owned.json').exists(): sys.exit(1)
        (root/'owned.json').unlink(missing_ok=True)
else:
    if args[0] == 'send' and (root/'hang').exists():
        (root/'uploader-pid').write_text(str(os.getpid()))
        time.sleep(60)
    if args[0] == 'health' and (root/'health-fail').exists(): sys.exit(1)
'''

class CarrierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for tool in ('nitro-cli', 'sandbox-bundle'):
            path = self.root/tool
            path.write_text(MOCK)
            path.chmod(0o755)
        env = dict(os.environ, PATH=str(self.root)+os.pathsep+os.environ['PATH'],
                   CARRIER_TEST_ROOT=str(self.root), WORKER_TOOL=str(self.root/'sandbox-bundle'),
                   WORKER_READY_FILE=str(self.root/'ready'), BOOTSTRAP_TIMEOUT_SECONDS='1',
                   POLL_SECONDS='1', RETRY_SECONDS='1')
        self.env = env
        self.process = None

    def tearDown(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try: self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
        self.temp.cleanup()

    def start(self):
        self.process = subprocess.Popen(['bash', str(SCRIPT)], env=self.env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    def wait_for(self, name):
        until = time.monotonic()+6
        while time.monotonic()<until:
            if (self.root/name).exists(): return
            if self.process.poll() is not None: self.fail('carrier exited unexpectedly')
            time.sleep(.02)
        self.fail(f'carrier did not create {name}')

    def test_ready_then_shutdown_terminates_only_owned_enclave(self):
        self.start(); self.wait_for('ready')
        self.process.send_signal(signal.SIGTERM)
        self.assertEqual(self.process.wait(timeout=8), 0)
        self.assertFalse((self.root/'ready').exists())
        self.assertTrue((self.root/'terminated').exists())
        self.assertFalse((self.root/'owned.json').exists())

    def test_disappeared_enclave_is_replaced(self):
        self.start(); self.wait_for('ready')
        (self.root/'owned.json').unlink()
        self.wait_for('terminated')
        self.wait_for('owned.json')
        self.wait_for('ready')
        self.assertIsNone(self.process.poll())

    def test_watchdog_kills_uploader_and_cleans_owned_enclave(self):
        (self.root/'hang').touch(); self.start(); self.wait_for('uploader-pid')
        pid = int((self.root/'uploader-pid').read_text())
        self.wait_for('terminated')
        self.assertFalse((self.root/'ready').exists())
        with self.assertRaises(ProcessLookupError): os.kill(pid, 0)

    def test_provisioning_ack_does_not_imply_serving_readiness(self):
        (self.root/'health-fail').touch(); self.start(); self.wait_for('terminated')
        self.assertFalse((self.root/'ready').exists())

if __name__ == '__main__':
    if not shutil.which('timeout') or not shutil.which('jq'):
        raise SystemExit('GNU timeout and jq are required')
    unittest.main()
