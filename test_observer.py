import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "collect", Path(__file__).parent / "host-observer" / "collect.py")
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)


class HostObserver(unittest.TestCase):
    def test_mount_table(self):
        table = b"1 0 0:1 / / rw - overlay overlay rw\n"
        table += b"2 1 8:1 / /data\\040drive rw - ext4 /dev/sda1 rw\n"
        table += b"3 1 0:2 / /proc rw - proc proc rw\n"
        table += b"4 1 0:3 / /nfs rw - nfs storage:/share rw\n"
        self.assertEqual(collect.mount_records(table),
                         [("/", "overlay", "overlay"), ("/data drive", "/dev/sda1", "ext4"),
                          ("/nfs", "storage:/share", "nfs")])

    def test_journal_arguments_not_caller_controlled(self):
        self.assertIn("_TRANSPORT=kernel", collect.journal_args())
        self.assertEqual(collect.journal_args("docker.service")[-2:], ["--unit", "docker.service"])
        for value in ("--help.service", "foo*.service", "../sshd.service"):
            with self.assertRaises(ValueError):
                collect.journal_args(value)

    def test_atomic_publish(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "snapshot"
            collect.publish(target, b"first")
            with target.open("rb") as old:
                collect.publish(target, b"next")
                self.assertEqual(old.read(), b"first")
            self.assertEqual(target.read_bytes(), b"next")
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
