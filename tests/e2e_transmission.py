"""Interoperability with an independent Transmission daemon on loopback.

Requires transmission-daemon on PATH and a built Rustorrent binary.
python3 tests/e2e_transmission.py [path/to/rustorrent]
"""
import base64
import http.client
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from e2e_transfer import App, PAYLOAD, bencode, free_port, make_torrent, wait_for


class InteropTests(unittest.TestCase):
    def run_transfer(self, rustorrent_seeds, encryption=1, dial_out=False):
        with tempfile.TemporaryDirectory(prefix='rustorrent-transmission-') as directory:
            root = Path(directory)
            rust_root, tr_root, config = (root / name for name in ('rustorrent', 'transmission', 'config'))
            for folder in (rust_root, tr_root, config):
                folder.mkdir()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect(('192.0.2.1', 9))
                peer_ip = route.getsockname()[0]
            if dial_out and not any(ipaddress.ip_address(peer_ip) in ipaddress.ip_network(net)
                                   for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
                self.skipTest(f'needs a LAN address, this host has {peer_ip}')
            app = App(rust_root)
            if rustorrent_seeds:
                (rust_root / 'fixture.bin').write_bytes(PAYLOAD)
            else:
                (tr_root / 'fixture.bin').write_bytes(PAYLOAD)
            rpc_port, tr_port = free_port(), free_port()
            settings = {'rpc-authentication-required': False, 'rpc-whitelist-enabled': True,
                        'rpc-whitelist': '127.0.0.1', 'rpc-host-whitelist-enabled': False,
                        'rpc-bind-address': '127.0.0.1', 'peer-exchange-enabled': False,
                        'dht-enabled': False, 'lpd-enabled': False, 'utp-enabled': False,
                        'port-forwarding-enabled': False, 'encryption': encryption,
                        'download-dir': str(tr_root), 'cache-size-mb': 2}
            (config / 'settings.json').write_text(json.dumps(settings))

            class Tracker(BaseHTTPRequestHandler):
                def do_GET(self):
                    # dial_out tells only Rustorrent about Transmission, over
                    # the LAN address, so the seed has to connect out itself.
                    port = parse_qs(urlsplit(self.path).query).get('port', [''])[0]
                    if not dial_out:
                        peers = socket.inet_aton(peer_ip) + struct.pack('!H', app.port)
                    elif port == str(app.port):
                        peers = socket.inet_aton(peer_ip) + struct.pack('!H', tr_port)
                    else:
                        peers = b''
                    body = bencode({b'interval': 1, b'peers': peers, b'complete': 1, b'incomplete': 1})
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *args):
                    pass

            tracker = ThreadingHTTPServer(('127.0.0.1', 0), Tracker)
            threading.Thread(target=tracker.serve_forever, daemon=True).start()
            torrent, _, metadata = make_torrent()
            announce = f'http://127.0.0.1:{tracker.server_port}/announce'.encode()
            torrent = b'd8:announce' + bencode(announce) + b'4:info' + metadata + b'e'
            daemon = None
            session_id = ''

            def rpc(method, arguments=None):
                nonlocal session_id
                for _ in range(2):
                    conn = http.client.HTTPConnection('127.0.0.1', rpc_port, timeout=3)
                    conn.request('POST', '/transmission/rpc', json.dumps({'method': method, 'arguments': arguments or {}}),
                                 {'X-Transmission-Session-Id': session_id})
                    response = conn.getresponse()
                    raw = response.read()
                    if response.status == 409:
                        session_id = response.getheader('X-Transmission-Session-Id')
                        conn.close()
                        continue
                    conn.close()
                    result = json.loads(raw)
                    self.assertEqual(result['result'], 'success', result)
                    return result['arguments']
                self.fail('Transmission RPC authentication failed')

            log = open(root / 'transmission.log', 'wb')
            try:
                app.start()
                tid = app.add(torrent)
                daemon = subprocess.Popen(['transmission-daemon', '--foreground', '--config-dir', str(config),
                    '--port', str(rpc_port), '--peerport', str(tr_port), '--no-portmap', '--no-dht', '--no-lpd',
                    '--no-utp', '--no-auth'], stdout=log, stderr=log)
                wait_for(lambda: rpc('session-get'), seconds=15)
                rpc('session-set', {'encryption': 'required' if encryption == 2 else 'preferred'})
                self.assertEqual(rpc('session-get')['encryption'], 'required' if encryption == 2 else 'preferred')
                rpc('torrent-add', {'metainfo': base64.b64encode(torrent).decode(), 'download-dir': str(tr_root)})
                if rustorrent_seeds:
                    wait_for(lambda: rpc('torrent-get', {'fields': ['percentDone']})['torrents'][0]['percentDone'] == 1, seconds=40)
                    self.assertEqual((tr_root / 'fixture.bin').read_bytes(), PAYLOAD)
                    wait_for(lambda: app.torrent(tid)['uploaded_bytes'] >= len(PAYLOAD))
                else:
                    wait_for(lambda: app.torrent(tid)['percent'] == 10000, seconds=40)
                    self.assertEqual((rust_root / 'fixture.bin').read_bytes(), PAYLOAD)
            except Exception:
                print('Transmission state:', rpc('torrent-get', {'fields': ['name','status','errorString','percentDone','peers','trackerStats']}), flush=True)
                print((rust_root / 'process.log').read_text(errors='replace')[-5000:], flush=True)
                raise
            finally:
                if daemon and daemon.poll() is None:
                    daemon.terminate()
                    daemon.wait(10)
                app.stop()
                app.log.close()
                tracker.shutdown()
                tracker.server_close()
                log.close()

    def test_upload_to_transmission(self):
        self.run_transfer(True)

    def test_seed_connects_out_to_lan_leecher(self):
        self.run_transfer(True, dial_out=True)

    def test_download_from_transmission(self):
        self.run_transfer(False)

    def test_required_encryption_upload_to_transmission(self):
        self.run_transfer(True, encryption=2)


if __name__ == '__main__':
    if not shutil.which('transmission-daemon'):
        raise SystemExit('Install transmission-daemon to run the interoperability gate.')
    unittest.main(verbosity=2)
