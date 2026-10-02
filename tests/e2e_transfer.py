"""Real-process BitTorrent tests. No public trackers or downloaded test data.

Run after cargo build: python3 tests/e2e_transfer.py [path/to/rustorrent]
The independent peer fixture speaks the wire protocol using Python's standard library.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import threading
import socketserver
import re
from urllib.parse import urlencode

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else 'target/debug/rustorrent').resolve())
PIECE = 32768
PAYLOAD = bytes((i * 31 + i // 13) % 256 for i in range(PIECE * 4 + 123))


def bencode(value):
    if isinstance(value, int):
        return b'i' + str(value).encode() + b'e'
    if isinstance(value, bytes):
        return str(len(value)).encode() + b':' + value
    if isinstance(value, list):
        return b'l' + b''.join(map(bencode, value)) + b'e'
    return b'd' + b''.join(bencode(k) + bencode(v) for k, v in sorted(value.items())) + b'e'


def make_torrent(name=b'fixture.bin', multi=False, private=True):
    info = {b'name': name, b'piece length': PIECE, b'private': 1 if private else 0,
            b'pieces': b''.join(hashlib.sha1(PAYLOAD[i:i+PIECE]).digest() for i in range(0, len(PAYLOAD), PIECE))}
    if multi:
        info[b'files'] = [{b'length': PIECE * 2, b'path': [b'first.bin']},
                          {b'length': len(PAYLOAD) - PIECE * 2, b'path': [b'second.bin']}]
    else:
        info[b'length'] = len(PAYLOAD)
    encoded = bencode(info)
    return bencode({b'info': info}), hashlib.sha1(encoded).digest(), encoded


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(callback, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = callback()
            if result:
                return result
        except (OSError, http.client.HTTPException, KeyError, IndexError):
            pass
        time.sleep(.05)
    raise AssertionError('timed out waiting for application state')


def read_exact(sock, size):
    output = bytearray()
    while len(output) < size:
        chunk = sock.recv(size - len(output))
        if not chunk:
            raise EOFError('peer closed connection')
        output.extend(chunk)
    return bytes(output)


def message(sock):
    size, = struct.unpack('!I', read_exact(sock, 4))
    if size > 2 * 1024 * 1024:
        raise AssertionError('unbounded wire message')
    return read_exact(sock, size)


def send(sock, kind, payload=b''):
    sock.sendall(struct.pack('!IB', len(payload) + 1, kind) + payload)


class App:
    def __init__(self, root):
        self.root = Path(root)
        self.ui = free_port()
        self.port = free_port()
        self.log = open(self.root / 'process.log', 'ab', buffering=0)
        self.process = None

    def start(self, extra=None, utp=False):
        self.process = subprocess.Popen([BINARY, '--ui', '--ui-addr', f'127.0.0.1:{self.ui}',
            '--port', str(self.port), '--no-port-mapping'] + ([] if utp else ['--no-utp']) + [
            '--max-peers', '4', '--max-peers-torrent', '2', '--download-dir', str(self.root)] + (extra or []),
            stdout=self.log, stderr=self.log)
        wait_for(lambda: self.get('/status'))

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
                raise AssertionError('application did not shut down within 15 seconds')

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.ui, timeout=5)
        try:
            conn.request(method, path, body, headers or {})
            response = conn.getresponse()
            data = response.read()
            return response.status, json.loads(data)
        finally:
            conn.close()

    def get(self, path):
        status, data = self.request('GET', path)
        assert status == 200, (status, data)
        return data

    def post(self, path, body=b'', content_type='application/x-www-form-urlencoded', expected=200):
        token = self.get('/api-token')['token']
        status, data = self.request('POST', path, body, {'Origin': f'http://127.0.0.1:{self.ui}',
            'X-Rustorrent-Token': token, 'Content-Type': content_type})
        assert status == expected, (status, data)
        return data

    def add(self, torrent, **options):
        result = self.post('/add-torrent?' + urlencode(options), torrent, 'application/x-bittorrent')
        tid = result['torrent_id']
        wait_for(lambda: self.torrent(tid)['status'] not in ('queued', 'loading', ''))
        return tid

    def torrent(self, tid):
        return next(t for t in self.get('/status')['torrents'] if t['id'] == tid)

    def peer(self, info_hash):
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        sock.settimeout(5)
        sock.sendall(b'\x13BitTorrent protocol' + b'\0'*5 + b'\x10\0\0' + info_hash + b'-PY0001-' + os.urandom(12))
        reply = read_exact(sock, 68)
        assert reply[28:48] == info_hash
        return sock


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rustorrent-e2e-')
        self.app = App(self.temp.name)
        self.app.start()

    def tearDown(self):
        try:
            self.app.stop()
        finally:
            self.app.log.close()
            if os.environ.get('RUSTORRENT_E2E_LOG'):
                print((self.app.root / 'process.log').read_text(errors='replace')[-16000:])
            self.temp.cleanup()

    def download(self, tid, info_hash, allowed=None):
        with self.app.peer(info_hash) as sock:
            send(sock, 5, b'\xf8')
            send(sock, 1)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                msg = message(sock)
                if msg and msg[0] == 6:
                    index, begin, size = struct.unpack('!III', msg[1:])
                    if allowed is not None:
                        self.assertIn(index, allowed, 'requested a deselected file')
                    offset = index * PIECE + begin
                    send(sock, 7, struct.pack('!II', index, begin) + PAYLOAD[offset:offset+size])
                if self.app.torrent(tid)['percent'] == 10000:
                    return
            self.fail('incoming seeder did not complete the download')

    def test_download_restart_metadata_upload_and_remove(self):
        torrent, info_hash, metadata = make_torrent()
        tid = self.app.add(torrent)
        self.download(tid, info_hash)
        self.assertEqual((self.app.root / 'fixture.bin').read_bytes(), PAYLOAD)
        self.app.stop()
        self.app.start()
        restored = wait_for(lambda: next((t for t in self.app.get('/status')['torrents'] if t['percent'] == 10000), None))
        tid = restored['id']
        with self.app.peer(info_hash) as sock:
            # Deliberately choose an ID different from Rustorrent's advertised ID 1.
            send(sock, 20, b'\0' + bencode({b'm': {b'ut_metadata': 7}}))
            send(sock, 20, b'\x01' + bencode({b'msg_type': 0, b'piece': 0}))
            metadata_seen = False
            unchoked = False
            send(sock, 2)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not (metadata_seen and unchoked):
                msg = message(sock)
                if msg[:2] == b'\x14\x07':
                    self.assertTrue(msg.endswith(metadata))
                    metadata_seen = True
                if msg == b'\x01':
                    unchoked = True
            self.assertTrue(metadata_seen, 'magnet metadata not served with peer extension ID')
            self.assertTrue(unchoked, 'interested leecher not unchoked')
            send(sock, 6, struct.pack('!III', 0, 0, 16384))
            msg = message(sock)
            while not msg or msg[0] != 7:
                msg = message(sock)
            self.assertEqual(msg[9:], PAYLOAD[:16384])
        wait_for(lambda: self.app.torrent(tid)['uploaded_bytes'] >= 16384)
        self.app.post(f'/torrent/delete?id={tid}&data=0')
        wait_for(lambda: not self.app.get('/status')['torrents'])
        self.assertEqual((self.app.root / 'fixture.bin').read_bytes(), PAYLOAD)

    def test_seed_closes_connections_to_other_seeds(self):
        torrent, info_hash, _ = make_torrent(private=False)
        tid = self.app.add(torrent)
        self.download(tid, info_hash)
        with self.app.peer(info_hash) as sock:
            send(sock, 20, b'\0' + bencode({b'm': {b'ut_pex': 3}}))
            send(sock, 5, b'\xf8')  # every piece: this peer is a seed too
            upload_only = False
            closed = False
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    msg = message(sock)
                except socket.timeout:
                    continue
                except (EOFError, ConnectionError):
                    closed = True
                    break
                if msg[:2] == b'\x14\x00' and b'11:upload_onlyi1e' in msg:
                    upload_only = True
            self.assertTrue(upload_only, 'a seed must advertise BEP 21 upload_only')
            self.assertTrue(closed, 'two seeds kept a connection that can carry nothing')

    def test_start_paused_and_file_selection_are_atomic(self):
        torrent, info_hash, _ = make_torrent(b'collection', multi=True)
        tid = self.app.add(torrent, paused=1, skip=1)
        self.assertTrue(self.app.torrent(tid)['paused'])
        self.assertEqual(self.app.torrent(tid)['files'][1]['priority'], 0)
        with self.app.peer(info_hash) as sock:
            send(sock, 5, b'\xf8')
            send(sock, 1)
            sock.settimeout(.8)
            try:
                while True:
                    msg = message(sock)
                    self.assertFalse(msg and msg[0] == 6, 'download request sent while paused')
            except socket.timeout:
                pass
        self.app.post(f'/torrent/resume?id={tid}')
        self.download(tid, info_hash, allowed={0, 1})
        self.assertEqual((self.app.root / 'collection' / 'first.bin').read_bytes(), PAYLOAD[:PIECE*2])
        self.app.post(f'/torrent/delete?id={tid}&data=1')
        wait_for(lambda: not self.app.get('/status')['torrents'])
        self.assertFalse((self.app.root / 'collection' / 'first.bin').exists())

    def test_invalid_add_is_rejected_before_queueing(self):
        self.app.post('/add-torrent', b'not a torrent', 'application/x-bittorrent', expected=400)
        self.app.post('/add-magnet', b'magnet=not-a-magnet', expected=400)
        torrent, _, _ = make_torrent()
        self.app.post('/add-torrent?skip=99', torrent, 'application/x-bittorrent', expected=409)
        self.assertFalse(self.app.get('/status')['torrents'])

    def test_crash_during_transfer_rechecks_and_resumes(self):
        torrent, info_hash, _ = make_torrent()
        tid = self.app.add(torrent)
        with self.app.peer(info_hash) as sock:
            send(sock, 5, b'\xf8')
            send(sock, 1)
            while self.app.torrent(tid)['completed_bytes'] < PIECE:
                msg = message(sock)
                if msg and msg[0] == 6:
                    index, begin, size = struct.unpack('!III', msg[1:])
                    offset = index * PIECE + begin
                    send(sock, 7, struct.pack('!II', index, begin) + PAYLOAD[offset:offset+size])
            self.app.process.kill()
            self.app.process.wait(5)
        self.app.start()
        restored = wait_for(lambda: next((t for t in self.app.get('/status')['torrents'] if t['files']), None))
        self.assertGreaterEqual(restored['completed_bytes'], PIECE)
        self.download(restored['id'], info_hash)
        self.assertEqual((self.app.root / 'fixture.bin').read_bytes(), PAYLOAD)

    def test_corrupt_peer_data_is_not_marked_complete(self):
        torrent, info_hash, _ = make_torrent()
        tid = self.app.add(torrent)
        with self.app.peer(info_hash) as sock:
            send(sock, 5, b'\xf8')
            send(sock, 1)
            try:
                for _ in range(30):
                    msg = message(sock)
                    if msg and msg[0] == 6:
                        index, begin, size = struct.unpack('!III', msg[1:])
                        send(sock, 7, struct.pack('!II', index, begin) + bytes([123])*size)
            except (EOFError, BrokenPipeError, ConnectionResetError):
                pass
        self.assertEqual(self.app.torrent(tid)['completed_bytes'], 0)
        self.download(tid, info_hash)
        self.assertEqual((self.app.root / 'fixture.bin').read_bytes(), PAYLOAD)

    def test_preallocation_does_not_truncate_larger_existing_file(self):
        sentinel = b'user file must survive' * 12000
        path = self.app.root / 'fixture.bin'
        path.write_bytes(sentinel)
        torrent, _, _ = make_torrent()
        result = self.app.post('/add-torrent?prealloc=1', torrent, 'application/x-bittorrent')
        wait_for(lambda: self.app.torrent(result['torrent_id'])['status'] == 'error')
        self.assertEqual(path.read_bytes(), sentinel)

    def test_stopping_a_rate_limited_upload_releases_the_peer(self):
        torrent, info_hash, _ = make_torrent()
        (self.app.root / 'fixture.bin').write_bytes(PAYLOAD)
        tid = self.app.add(torrent)
        self.app.post('/rate-limits', b'download_kbps=0&upload_kbps=1')
        with self.app.peer(info_hash) as sock:
            send(sock, 2)
            while message(sock) != b'\x01':
                pass
            send(sock, 6, struct.pack('!III', 0, 0, 16384))
            time.sleep(.1)
            started = time.monotonic()
            self.app.post(f'/torrent/stop?id={tid}')
            wait_for(lambda: self.app.torrent(tid)['active_peers'] == 0, seconds=5)
            self.assertLess(time.monotonic() - started, 5)
        self.app.stop()
        self.app.start()
        restored = wait_for(lambda: next((t for t in self.app.get('/status')['torrents'] if t['files']), None))
        self.assertTrue(restored['paused'])

    def test_magnet_metadata_uses_independent_incoming_and_outgoing_ids(self):
        _, _, basic_info = make_torrent()
        # A canonical extra key creates two metadata chunks, so replies must not
        # accidentally replace the extension ID used by subsequent requests.
        metadata = b'd7:comment' + bencode(b'x' * 20000) + basic_info[1:]
        info_hash = hashlib.sha1(metadata).digest()
        errors = []

        class ProxyPeer(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.settimeout(8)
                try:
                    version, count = read_exact(sock, 2)
                    assert version == 5
                    read_exact(sock, count)
                    sock.sendall(b'\x05\x00')
                    header = read_exact(sock, 4)
                    assert header[:3] == b'\x05\x01\x00'
                    if header[3] == 1:
                        read_exact(sock, 4)
                    elif header[3] == 3:
                        read_exact(sock, read_exact(sock, 1)[0])
                    else:
                        read_exact(sock, 16)
                    read_exact(sock, 2)
                    sock.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
                    handshake = read_exact(sock, 68)
                    assert handshake[28:48] == info_hash
                    sock.sendall(handshake[:48] + b'-PYMETA-' + os.urandom(12))
                    send(sock, 20, b'\0' + bencode({b'm': {b'ut_metadata': 7}, b'metadata_size': len(metadata)}))
                    served = set()
                    while len(served) < 2:
                        msg = message(sock)
                        if msg[:1] != b'\x14' or msg[1] == 0:
                            continue
                        assert msg[1] == 7, 'client replaced our extension ID with its own'
                        index = int(re.search(br'5:piecei([0-9]+)e', msg).group(1))
                        body = bencode({b'msg_type': 1, b'piece': index, b'total_size': len(metadata)})
                        send(sock, 20, b'\x01' + body + metadata[index*16384:(index+1)*16384])
                        served.add(index)
                except Exception as error:
                    errors.append(str(error))

        with socketserver.ThreadingTCPServer(('127.0.0.1', 0), ProxyPeer) as proxy:
            proxy.daemon_threads = True
            threading.Thread(target=proxy.serve_forever, daemon=True).start()
            try:
                self.app.stop()
                self.app.start(['--proxy', f'socks5://127.0.0.1:{proxy.server_address[1]}'])
                magnet = f'magnet:?xt=urn:btih:{info_hash.hex()}&x.pe=1.1.1.1:6881'
                result = self.app.post('/add-magnet', urlencode({'magnet': magnet, 'paused': 1}).encode())
                item = wait_for(lambda: self.app.torrent(result['torrent_id']) if self.app.torrent(result['torrent_id'])['files'] else None, seconds=20)
                self.assertEqual(item['info_hash'], info_hash.hex())
                self.assertTrue(item['paused'])
                self.assertEqual(errors, [])
            finally:
                proxy.shutdown()


def holepunch_msg(kind, addr, code=0):
    host, port = addr
    return bytes([kind, 0]) + socket.inet_aton(host) + struct.pack('!HI', port, code)


class HolepunchTests(unittest.TestCase):
    """BEP 55 over real sockets: Rustorrent as the relay and as the target."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rustorrent-e2e-')
        self.app = App(self.temp.name)
        self.app.start(utp=True)
        torrent, self.info_hash, _ = make_torrent(private=False)
        self.app.add(torrent)

    def tearDown(self):
        try:
            self.app.stop()
        finally:
            self.app.log.close()
            if os.environ.get('RUSTORRENT_E2E_LOG'):
                print((self.app.root / 'process.log').read_text(errors='replace')[-16000:])
            self.temp.cleanup()

    def punch_peer(self, ext_id):
        """Connects, advertises ut_holepunch and returns the peer's own
        ut_holepunch ID from Rustorrent's extended handshake."""
        sock = self.app.peer(self.info_hash)
        send(sock, 20, b'\0' + bencode({b'm': {b'ut_holepunch': ext_id}}))
        while True:
            msg = message(sock)
            if msg[:2] == b'\x14\x00':
                found = re.search(br'12:ut_holepunchi([0-9]+)e', msg)
                self.assertIsNotNone(found, 'ut_holepunch not advertised')
                return sock, int(found.group(1))

    def next_holepunch(self, sock, ext_id):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            msg = message(sock)
            if msg[:2] == bytes([20, ext_id]):
                return msg[2:]
        self.fail('no ut_holepunch message')

    def test_relay_introduces_two_connected_peers(self):
        first, their_id = self.punch_peer(5)
        second, _ = self.punch_peer(6)
        with first, second:
            first_addr = first.getsockname()
            second_addr = second.getsockname()
            # Both connections register with the relay asynchronously: until
            # the second one has, the answer is "not connected" (error 2), and
            # until its extension handshake is read, "no support" (error 3).
            pending = {holepunch_msg(2, second_addr, code) for code in (2, 3)}
            deadline = time.monotonic() + 10
            while True:
                send(first, 20, bytes([their_id]) + holepunch_msg(0, second_addr))
                reply = self.next_holepunch(first, 5)
                if reply not in pending or time.monotonic() > deadline:
                    break
                time.sleep(.1)
            self.assertEqual(reply, holepunch_msg(1, second_addr))
            self.assertEqual(self.next_holepunch(second, 6), holepunch_msg(1, first_addr))
            send(first, 20, bytes([their_id]) + holepunch_msg(0, ('127.0.0.1', 9)))
            self.assertEqual(self.next_holepunch(first, 5), holepunch_msg(2, ('127.0.0.1', 9), 2))

    def test_connect_message_opens_a_connection_to_the_target(self):
        target = socket.socket()
        target.bind(('127.0.0.1', 0))
        target.listen(1)
        target.settimeout(10)
        relay, their_id = self.punch_peer(5)
        with relay, target:
            send(relay, 20, bytes([their_id]) + holepunch_msg(1, target.getsockname()))
            conn, _ = target.accept()
            with conn:
                conn.settimeout(5)
                handshake = read_exact(conn, 68)
                self.assertEqual(handshake[28:48], self.info_hash)


if __name__ == '__main__':
    unittest.main(verbosity=2)
