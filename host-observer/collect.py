#!/usr/bin/env python3
"""Publish bounded read-only host snapshots for container-log-api."""
import argparse
import json
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

PSEUDO = set("""autofs bpf cgroup cgroup2 configfs debugfs devpts devtmpfs
efivarfs fusectl hugetlbfs mqueue nsfs proc pstore ramfs securityfs sysfs
tmpfs tracefs binfmt_misc rpc_pipefs overlay""".split())
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,99}\.service")
MOUNT_ESCAPE = re.compile(rb"\\([0-7]{3})")
MAX_MOUNTS = 512
MAX_JOURNAL_BYTES = 512 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def counters():
    with open("/proc/stat", encoding="ascii") as f:
        fields = f.readline().split()
    return list(map(int, fields[1:9]))


def resources():
    start = counters()
    time.sleep(1)
    delta = [max(0, b - a) for a, b in zip(start, counters())]
    total = sum(delta)
    def pct(n):
        return round(n * 100 / total, 2) if total else None

    wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in wanted:
            mem[key] = int(value.split()[0]) * 1024
    return {
        "sampled_at": utc_now(),
        "cpu": {"busy_pct": pct(sum(delta[:3]) + sum(delta[5:7])),
                "iowait_pct": pct(delta[4]), "steal_pct": pct(delta[7]),
                "logical_cpus": os.cpu_count(), "load_average": list(os.getloadavg())},
        "memory": {"total_bytes": mem["MemTotal"], "available_bytes": mem["MemAvailable"],
                   "used_bytes": mem["MemTotal"] - mem["MemAvailable"]},
        "swap": {"total_bytes": mem["SwapTotal"], "free_bytes": mem["SwapFree"]},
    }


def decode_mount(value):
    return os.fsdecode(MOUNT_ESCAPE.sub(lambda m: bytes([int(m[1], 8)]), value))


def mount_records(data):
    mounts = {}
    for line in data.splitlines():
        left, sep, right = line.partition(b" - ")
        a, b = left.split(), right.split()
        if not sep or len(a) < 6 or len(b) < 2:
            continue
        mount = decode_mount(a[4])
        kind = decode_mount(b[0])
        # Last visible mount wins; an overmounted entry is not a second filesystem.
        mounts[mount] = (decode_mount(b[1]), kind)
    return [(m, src, kind) for m, (src, kind) in sorted(mounts.items())
            if m == "/" or kind not in PSEUDO]


def filesystem_usage():
    mounts = mount_records(Path("/proc/self/mountinfo").read_bytes())
    rows = []
    for mount, device, fs in mounts[:MAX_MOUNTS]:
        row = {"mount": mount, "device": device, "type": fs}
        try:
            s = os.statvfs(mount)
            block = s.f_frsize or s.f_bsize
            row.update(total_bytes=s.f_blocks * block,
                       used_bytes=(s.f_blocks - s.f_bfree) * block,
                       available_bytes=max(0, s.f_bavail) * block,
                       inodes_total=s.f_files, inodes_free=s.f_favail)
        except OSError:
            row["error"] = "unavailable"
        rows.append(row)
    return {"sampled_at": utc_now(), "mounts": rows, "truncated": len(mounts) > MAX_MOUNTS}


def publish(path, payload):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".snapshot-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def journal_args(unit=None):
    args = ["journalctl", "--no-pager", "--utc", "--quiet", "--output=short-iso-precise", "--lines=250"]
    if unit is None:
        # Match kernel transport without implying --boot, keeping previous boots available.
        return args + ["_TRANSPORT=kernel"]
    if not UNIT.fullmatch(unit):
        raise ValueError("invalid unit")
    return args + ["--unit", unit]


def journal_snapshot(unit):
    with subprocess.Popen(journal_args(unit), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env={**os.environ, "SYSTEMD_COLORS": "0"}) as proc:
        data = proc.stdout.read(MAX_JOURNAL_BYTES + 1)
        if len(data) > MAX_JOURNAL_BYTES:
            proc.kill()
            proc.wait()
            raise RuntimeError("journal output exceeded budget")
        if proc.wait() != 0:
            raise RuntimeError("journal query failed")
    return b"".join(line[:800] + b"\n" for line in data.splitlines())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--kernel", action="store_true")
    p.add_argument("--unit", action="append", default=[])
    p.add_argument("mode", choices=["metrics", "journal"])
    opt = p.parse_args()
    if len(opt.unit) > 8 or any(not UNIT.fullmatch(unit) for unit in opt.unit):
        p.error("invalid journal unit allowlist")
    if opt.mode == "metrics":
        for name, take in (("metrics", resources), ("filesystems", filesystem_usage)):
            publish(opt.output / (name + ".json"), json.dumps(take()).encode())
        return
    failed = False
    for unit in ([None] if opt.kernel else []) + opt.unit:
        name = "kernel" if unit is None else unit
        file = opt.output / ("journal-" + name + ".log")
        try:
            publish(file, journal_snapshot(unit))
        except (OSError, RuntimeError):
            file.unlink(missing_ok=True)
            print(f"Failed to refresh configured journal: {name}", flush=True)
            failed = True
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
