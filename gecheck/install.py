"""Установка движков: только официальные релизы, только закреплённые версии и SHA-256.

Если сумма скачанного файла не совпала с закреплённой — файл удаляется и установка
прерывается. Обновление версии движка = правка таблицы ENGINES и новый релиз GoldenEye Check.
"""

import hashlib
import io
import os
import platform
import stat
import tarfile
import urllib.request
import zipfile
from pathlib import Path

from .paths import engines_dir

GITLEAKS = "8.30.1"
OSV = "2.6.0"
OPENGREP = "1.30.0"

_GL = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS}/gitleaks_{GITLEAKS}_"
_OSV = f"https://github.com/google/osv-scanner/releases/download/v{OSV}/osv-scanner_"
_OG = f"https://github.com/opengrep/opengrep/releases/download/v{OPENGREP}/opengrep_"

# (движок, платформа) -> (url, sha256, тип упаковки)
ENGINES = {
    ("gitleaks", "windows-x64"): (_GL + "windows_x64.zip",
                                  "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e", "zip"),
    ("gitleaks", "linux-x64"): (_GL + "linux_x64.tar.gz",
                                "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb", "tar"),
    ("gitleaks", "macos-arm64"): (_GL + "darwin_arm64.tar.gz",
                                  "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5", "tar"),
    ("osv-scanner", "windows-x64"): (_OSV + "windows_amd64.exe",
                                     "e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6", "bin"),
    ("osv-scanner", "linux-x64"): (_OSV + "linux_amd64",
                                   "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108", "bin"),
    ("osv-scanner", "macos-arm64"): (_OSV + "darwin_arm64",
                                     "98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4", "bin"),
    ("opengrep", "windows-x64"): (_OG + "windows_x86.exe",
                                  "b5cf4f8fe9f44e030aab2d579d96bd395c139db1f1ba66633676ff4d5ebc7c39", "bin"),
    ("opengrep", "linux-x64"): (_OG + "manylinux_x86",
                                "35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c", "bin"),
    ("opengrep", "macos-arm64"): (_OG + "osx_arm64",
                                  "0f5bc3dec09d995c61331a4017b856ede508f90d95b018d95f1dc6166be89fdd", "bin"),
}

NAMES = ("gitleaks", "osv-scanner", "opengrep")


def current_platform() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arm = machine in ("arm64", "aarch64")
    if system == "windows" and not arm:
        return "windows-x64"
    if system == "linux" and not arm:
        return "linux-x64"
    if system == "darwin" and arm:
        return "macos-arm64"
    raise SystemExit(f"Платформа {system}/{machine} пока не поддерживается")


def exe_name(name: str) -> str:
    return name + (".exe" if os.name == "nt" else "")


def engine_path(name: str) -> Path:
    return engines_dir() / exe_name(name)


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "goldeneye-check-installer"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def _unpack(blob: bytes, kind: str, name: str) -> bytes:
    if kind == "bin":
        return blob
    wanted = exe_name(name)
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            return z.read(wanted)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        member = t.getmember(wanted)
        return t.extractfile(member).read()


def install(names=NAMES, force=False, log=print) -> None:
    plat = current_platform()
    target_dir = engines_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        dest = engine_path(name)
        if dest.exists() and not force:
            log(f"  {name}: уже установлен")
            continue
        url, sha, kind = ENGINES[(name, plat)]
        log(f"  {name}: скачиваю {url.rsplit('/', 1)[1]}")
        blob = _download(url)
        got = hashlib.sha256(blob).hexdigest()
        if got != sha:
            raise SystemExit(f"{name}: контрольная сумма не совпала ({got}), установка прервана")
        data = _unpack(blob, kind, name)
        tmp = dest.with_suffix(dest.suffix + ".part")
        tmp.write_bytes(data)
        tmp.replace(dest)
        if os.name != "nt":
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        log(f"  {name}: готово, SHA-256 совпала")
