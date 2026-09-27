"""uTP interoperability with libtorrent, the engine inside qBittorrent and Deluge.

Run after cargo build: python3 tests/e2e_libtorrent.py [path/to/rustorrent]
Needs the libtorrent Python bindings (apt install python3-libtorrent, or
pip install libtorrent); the tests are skipped without them. libtorrent's
TCP is switched off, so every byte crosses uTP.
"""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import e2e_transfer as e2e  # noqa: E402  (reads the binary path from argv)

try:
    import libtorrent as lt
except ImportError:
    lt = None


@unittest.skipIf(lt is None, 'libtorrent Python bindings are not installed')
class LibtorrentUtpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rustorrent-lt-')
        root = Path(self.temp.name)
        (root / 'app').mkdir()
        (root / 'lt').mkdir()
        self.lt_dir = root / 'lt'
        self.app = e2e.App(root / 'app')
        self.app.start(utp=True)
        self.torrent, self.info_hash, _ = e2e.make_torrent(private=False)
        self.session = lt.session({
            'listen_interfaces': f'127.0.0.1:{e2e.free_port()}',
            'enable_dht': False, 'enable_lsd': False, 'enable_upnp': False, 'enable_natpmp': False,
            'enable_outgoing_tcp': False, 'enable_incoming_tcp': False,
            'allow_multiple_connections_per_ip': True,
        })

    def tearDown(self):
        try:
            self.app.stop()
        finally:
            self.app.log.close()
            if os.environ.get('RUSTORRENT_E2E_LOG'):
                print((self.app.root / 'process.log').read_text(errors='replace')[-16000:])
            del self.session
            self.temp.cleanup()

    def add_to_libtorrent(self):
        params = lt.add_torrent_params()
        params.ti = lt.torrent_info(lt.bdecode(self.torrent))
        params.save_path = str(self.lt_dir)
        return self.session.add_torrent(params)

    def test_downloads_full_size_utp_packets_from_libtorrent(self):
        # libtorrent fills the path MTU, so its data packets are larger than
        # the ones Rustorrent sends; they used to reset the connection.
        (self.lt_dir / 'fixture.bin').write_bytes(e2e.PAYLOAD)
        handle = self.add_to_libtorrent()
        e2e.wait_for(lambda: handle.status().is_seeding)
        tid = self.app.add(self.torrent)
        handle.connect_peer(('127.0.0.1', self.app.port))
        e2e.wait_for(lambda: self.app.torrent(tid)['percent'] == 10000, seconds=30)
        self.assertEqual((self.app.root / 'fixture.bin').read_bytes(), e2e.PAYLOAD)

    def test_seeds_to_libtorrent_over_utp(self):
        (self.app.root / 'fixture.bin').write_bytes(e2e.PAYLOAD)
        tid = self.app.add(self.torrent)
        e2e.wait_for(lambda: self.app.torrent(tid)['percent'] == 10000)
        handle = self.add_to_libtorrent()
        handle.connect_peer(('127.0.0.1', self.app.port))
        e2e.wait_for(lambda: handle.status().is_seeding, seconds=30)
        self.assertEqual((self.lt_dir / 'fixture.bin').read_bytes(), e2e.PAYLOAD)
        e2e.wait_for(lambda: self.app.torrent(tid)['uploaded_bytes'] >= len(e2e.PAYLOAD))


if __name__ == '__main__':
    unittest.main(verbosity=2)
