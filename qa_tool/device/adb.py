"""Тонкая обёртка над adb. Работает на Windows/macOS/Linux."""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


class AdbError(RuntimeError):
    pass


def find_adb() -> str | None:
    found = shutil.which("adb")
    if found:
        return found
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.getenv(env)
        if root:
            for name in ("adb", "adb.exe"):
                cand = Path(root) / "platform-tools" / name
                if cand.is_file():
                    return str(cand)
    home = Path.home()
    for cand in (home / "Library/Android/sdk/platform-tools/adb",
                 home / "Android/Sdk/platform-tools/adb",
                 home / "AppData/Local/Android/Sdk/platform-tools/adb.exe"):
        if cand.is_file():
            return str(cand)
    return None


@dataclass
class DeviceInfo:
    serial: str
    state: str
    model: str = ""
    android: str = ""
    sdk: int = 0
    abis: list[str] = field(default_factory=list)
    is_emulator: bool = False
    screen: str = ""

    @property
    def title(self) -> str:
        kind = "эмулятор" if self.is_emulator else "устройство"
        return f"{self.model or self.serial} ({kind}, Android {self.android}, API {self.sdk})"


class Adb:
    def __init__(self, serial: str | None = None, adb_path: str | None = None, timeout: int = 120):
        self.path = adb_path or find_adb()
        if not self.path:
            raise AdbError("adb не найден. Установите Android SDK Platform-Tools и добавьте в PATH.")
        self.serial = serial
        self.timeout = timeout

    # ---- базовый вызов -------------------------------------------------
    def _base(self) -> list[str]:
        return [self.path] + (["-s", self.serial] if self.serial else [])

    def run(self, *args: str, timeout: int | None = None, check: bool = False) -> subprocess.CompletedProcess:
        cmd = self._base() + list(args)
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=timeout or self.timeout)
        except subprocess.TimeoutExpired as e:
            raise AdbError(f"adb {' '.join(args)}: таймаут {e.timeout} с") from e
        res.stdout_text = res.stdout.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
        res.stderr_text = res.stderr.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
        if check and res.returncode != 0:
            raise AdbError(f"adb {' '.join(args)} → {res.returncode}: {res.stderr_text.strip() or res.stdout_text.strip()}")
        return res

    def shell(self, cmd: str, timeout: int | None = None) -> str:
        res = self.run("shell", cmd, timeout=timeout)
        return (res.stdout_text + res.stderr_text).strip()  # type: ignore[attr-defined]

    # ---- устройства ------------------------------------------------------
    def devices(self) -> list[DeviceInfo]:
        res = subprocess.run([self.path, "devices", "-l"], capture_output=True, timeout=30)
        out = []
        for line in res.stdout.decode(errors="replace").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            model = next((p.split(":", 1)[1] for p in parts if p.startswith("model:")), "")
            out.append(DeviceInfo(serial=serial, state=state, model=model.replace("_", " "),
                                  is_emulator=serial.startswith("emulator-")))
        return out

    def select(self, preferred: str | None = None) -> DeviceInfo:
        devs = self.devices()
        ready = [d for d in devs if d.state == "device"]
        if preferred:
            match = [d for d in devs if d.serial == preferred]
            if not match:
                raise AdbError(f"Устройство {preferred} не найдено. Доступны: {', '.join(d.serial for d in devs) or 'нет'}")
            if match[0].state != "device":
                raise AdbError(f"Устройство {preferred} в состоянии «{match[0].state}» (нужно разрешить отладку по USB?)")
            dev = match[0]
        elif not ready:
            other = ", ".join(f"{d.serial}:{d.state}" for d in devs)
            raise AdbError("Нет подключённых устройств/эмуляторов" + (f" (есть: {other})" if other else "")
                           + ". Запустите эмулятор в Android Studio или `emulator -avd <имя>`.")
        else:
            ready.sort(key=lambda d: not d.is_emulator)
            dev = ready[0]
        self.serial = dev.serial
        return self.describe(dev)

    def describe(self, dev: DeviceInfo) -> DeviceInfo:
        props = self.getprops(["ro.product.model", "ro.build.version.release", "ro.build.version.sdk",
                               "ro.product.cpu.abilist", "ro.kernel.qemu"])
        dev.model = props.get("ro.product.model") or dev.model
        dev.android = props.get("ro.build.version.release", "")
        try:
            dev.sdk = int(props.get("ro.build.version.sdk") or 0)
        except ValueError:
            dev.sdk = 0
        dev.abis = [a for a in (props.get("ro.product.cpu.abilist") or "").split(",") if a]
        dev.is_emulator = dev.is_emulator or props.get("ro.kernel.qemu") == "1"
        size = self.shell("wm size")
        dev.screen = size.split(":")[-1].strip() if ":" in size else ""
        return dev

    def getprops(self, names: list[str]) -> dict[str, str]:
        out = {}
        for n in names:
            out[n] = self.shell(f"getprop {n}").strip()
        return out

    def wait_boot(self, timeout: int = 120) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.shell("getprop sys.boot_completed").strip() == "1":
                return True
            time.sleep(2)
        return False

    # ---- приложение ----------------------------------------------------
    def is_installed(self, package: str) -> bool:
        return f"package:{package}" in self.shell(f"pm list packages {package}").split()

    def uninstall(self, package: str) -> str:
        res = self.run("uninstall", package, timeout=120)
        return (res.stdout_text + res.stderr_text).strip()  # type: ignore[attr-defined]

    def install(self, apk: str, grant: bool = True, test_only: bool = False) -> tuple[bool, str]:
        args = ["install", "-r"]
        if grant:
            args.append("-g")
        if test_only:
            args.append("-t")
        res = self.run(*args, apk, timeout=600)
        text = (res.stdout_text + res.stderr_text).strip()  # type: ignore[attr-defined]
        ok = res.returncode == 0 and "Success" in text
        return ok, text

    def force_stop(self, package: str) -> None:
        self.shell(f"am force-stop {package}")

    def pidof(self, package: str) -> str:
        out = self.shell(f"pidof {package}")
        if out and out.split()[0].isdigit():
            return out
        # Старые Android без pidof: ищем в ps
        for line in self.shell("ps -A 2>/dev/null || ps").splitlines():
            parts = line.split()
            if parts and parts[-1] == package and len(parts) > 1 and parts[1].isdigit():
                return parts[1]
        return ""

    def screenshot(self, dest: Path) -> bool:
        res = self.run("exec-out", "screencap", "-p", timeout=30)
        if res.returncode == 0 and res.stdout[:8] == b"\x89PNG\r\n\x1a\n":
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(res.stdout)
            return True
        return False

    def logcat_clear(self) -> None:
        self.run("logcat", "-c", timeout=30)

    def logcat_start(self, dest: Path) -> subprocess.Popen:
        dest.parent.mkdir(parents=True, exist_ok=True)
        f = dest.open("wb")
        proc = subprocess.Popen(self._base() + ["logcat", "-v", "threadtime", "-b", "main", "-b", "system", "-b", "crash"],
                                stdout=f, stderr=subprocess.STDOUT)
        proc._qa_file = f  # type: ignore[attr-defined]
        return proc

    @staticmethod
    def logcat_stop(proc: subprocess.Popen) -> None:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            proc.kill()
        finally:
            f = getattr(proc, "_qa_file", None)
            if f:
                f.close()
