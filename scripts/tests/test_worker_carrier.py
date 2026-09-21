"""Carrier lifecycle checks with a foreign enclave present and the real supervisor."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "run-worker-enclave.sh"
RELEASE_ID = "biometric-engines-worker-v0.1.0"
ARTIFACT_URI = (
    "s3://biometric-engines-worker-dev-eu-central-1/worker/v0.1.0/"
    f"{RELEASE_ID}-x86_64-unknown-linux-gnu.tar.gz"
)
MOCK = '''#!/usr/bin/env python3
import json, os, shutil, sys, time
from pathlib import Path
root = Path(os.environ['CARRIER_TEST_ROOT'])
args = sys.argv[1:]
if Path(sys.argv[0]).name == 'nitro-cli':
    if args[0] == 'run-enclave':
        with (root/'run-enclave.log').open('a') as log: log.write('1\\n')
        enclave_name = args[args.index('--enclave-name')+1]
        item = dict(EnclaveID='owned', EnclaveCID=99, EnclaveName=enclave_name, State='RUNNING')
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
elif Path(sys.argv[0]).name == 'aws':
    assert args[:2] == ['s3', 'cp'], args
    if (root/'download-fail').exists():
        (root/'download-fail').unlink()
        (root/'download-failed').touch()
        sys.exit(1)
    shutil.copy(root/'artifact.tar.gz', args[-1])
    (root/'downloaded').touch()
    with (root/'download.log').open('a') as log: log.write('1\\n')
else:
    if args[0] == 'manifest':
        assert args[1] == os.environ['WORKER_RELEASE_ID'], args
        assert Path(args[2]).name == 'biometric-engines-worker' and Path(args[2]).is_file(), args
        print('{}')
    elif args[0] == 'pack':
        assert Path(args[1]).is_file() and Path(args[2]).is_file(), args
        Path(args[3]).write_bytes(b'bundle')
        (root/'packed').touch()
    elif args[0] == 'send':
        assert Path(args[2]).is_file(), args
        (root/'sent').touch()
        if (root/'hang').exists():
            (root/'uploader-pid').write_text(str(os.getpid()))
            time.sleep(60)
    elif args[0] == 'health' and (root/'health-fail').exists():
        sys.exit(1)
'''

class CarrierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for tool in ('nitro-cli', 'sandbox-bundle', 'aws'):
            path = self.root/tool
            path.write_text(MOCK)
            path.chmod(0o755)
        self.artifact_sha256 = self.make_artifact()
        env = dict(os.environ, PATH=str(self.root)+os.pathsep+os.environ['PATH'],
                   CARRIER_TEST_ROOT=str(self.root), WORKER_TOOL=str(self.root/'sandbox-bundle'),
                   WORKER_READY_FILE=str(self.root/'ready'), BOOTSTRAP_TIMEOUT_SECONDS='3',
                   DRAIN_SECONDS='0', POLL_SECONDS='1', RETRY_SECONDS='1',
                   WORKER_ARTIFACT_URI=ARTIFACT_URI, WORKER_ARTIFACT_SHA256=self.artifact_sha256,
                   WORKER_RELEASE_ID=RELEASE_ID)
        self.env = env
        self.process = None

    def make_artifact(self):
        """A tarball shaped like the published worker artifact; returns its sha256."""
        top = f"{RELEASE_ID}-x86_64-unknown-linux-gnu"
        source = self.root/'fixture'/top
        source.mkdir(parents=True)
        (source/'biometric-engines-worker').write_bytes(b'\\x7fELF' + b'worker'*64)
        with tarfile.open(self.root/'artifact.tar.gz', 'w:gz') as archive:
            archive.add(source, arcname=top)
        return hashlib.sha256((self.root/'artifact.tar.gz').read_bytes()).hexdigest()

    def tearDown(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try: self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
        self.temp.cleanup()

    def start(self, timeout=None):
        env = self.env if timeout is None else dict(self.env, BOOTSTRAP_TIMEOUT_SECONDS=timeout)
        self.process = subprocess.Popen(['bash', str(SCRIPT)], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    def wait_for(self, name):
        until = time.monotonic()+6
        while time.monotonic()<until:
            if (self.root/name).exists(): return
            if self.process.poll() is not None: self.fail('carrier exited unexpectedly')
            time.sleep(.02)
        self.fail(f'carrier did not create {name}')

    def wait_for_downloads(self, count):
        """Wait until the mock has served `count` downloads, proving an attempt ran."""
        until = time.monotonic()+6
        while time.monotonic()<until:
            log = self.root/'download.log'
            if log.exists() and len(log.read_text().splitlines()) >= count: return
            if self.process.poll() is not None: self.fail('carrier exited unexpectedly')
            time.sleep(.02)
        self.fail(f'carrier did not download {count} times')

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
        (self.root/'hang').touch(); self.start(timeout='1'); self.wait_for('uploader-pid')
        pid = int((self.root/'uploader-pid').read_text())
        self.wait_for('terminated')
        self.assertFalse((self.root/'ready').exists())
        with self.assertRaises(ProcessLookupError): os.kill(pid, 0)

    def test_provisioning_ack_does_not_imply_serving_readiness(self):
        (self.root/'health-fail').touch(); self.start(timeout='1'); self.wait_for('terminated')
        self.assertFalse((self.root/'ready').exists())

    def test_artifact_is_downloaded_verified_packed_then_sent(self):
        self.start(); self.wait_for('ready')
        for stage in ('downloaded', 'packed', 'sent'):
            self.assertTrue((self.root/stage).exists(), f'{stage} did not run')

    def test_digest_mismatch_fails_attempt_without_sending(self):
        self.env['WORKER_ARTIFACT_SHA256'] = '0'*64
        self.start(); self.wait_for('downloaded')
        self.wait_for_downloads(2)
        self.assertFalse((self.root/'run-enclave.log').exists())
        self.assertFalse((self.root/'packed').exists())
        self.assertFalse((self.root/'sent').exists())
        self.assertFalse((self.root/'ready').exists())

    def test_failed_download_launches_no_enclave_and_is_retried(self):
        (self.root/'download-fail').touch()
        self.start(); self.wait_for('ready')
        self.assertTrue((self.root/'download-failed').exists())
        self.assertFalse((self.root/'terminated').exists())
        launches = (self.root/'run-enclave.log').read_text().splitlines()
        self.assertEqual(len(launches), 1, 'a failed download launched an enclave')
        for stage in ('downloaded', 'packed', 'sent'):
            self.assertTrue((self.root/stage).exists(), f'{stage} did not run')

if __name__ == '__main__':
    if not shutil.which('timeout') or not shutil.which('jq'):
        raise SystemExit('GNU timeout and jq are required')
    unittest.main()
