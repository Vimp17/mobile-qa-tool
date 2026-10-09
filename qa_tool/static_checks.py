"""Статические проверки APK (без устройства) и сравнение с предыдущей сборкой."""
from __future__ import annotations

from typing import Any

from .apk.apk import ApkInfo
from .apk.dex import host_matches
from .config import Config
from .models import CheckResult, Status

LOCAL_HOSTS = ("localhost", "127.0.0.1", "10.0.2.2", "0.0.0.0")


def _c(id_, title, status, details="", items=None, **extra) -> CheckResult:
    return CheckResult(id=id_, title=title, status=status, details=details,
                       items=list(items or []), category="static", extra=extra)


def run_static_checks(apk: ApkInfo, cfg: Config, prev: dict[str, Any] | None = None,
                      expect_version: str | None = None) -> list[CheckResult]:
    st = cfg["static"]
    release = cfg.get_path("project.build_type", "release") == "release"
    bt = "release" if release else "debug"
    out: list[CheckResult] = []

    # S01 — тот ли это пакет
    expected_id = (cfg.get_path("project.expected_app_id") or "").strip()
    if expected_id:
        if apk.package == expected_id:
            out.append(_c("S01", "Пакет приложения", Status.PASS, f"{apk.package}"))
        else:
            out.append(_c("S01", "Пакет приложения", Status.FAIL,
                          f"Ожидался {expected_id}, в APK {apk.package}. Похоже, прислали другой флейвор/сборку."))
    else:
        out.append(_c("S01", "Пакет приложения", Status.INFO,
                      f"{apk.package} (ожидаемый пакет не задан в qa.yaml → project.expected_app_id)"))

    # S02 — версия
    if expect_version:
        ok = expect_version in (apk.version_name, str(apk.version_code))
        out.append(_c("S02", "Версия сборки", Status.PASS if ok else Status.FAIL,
                      f"{apk.version_name} ({apk.version_code}); ожидалась {expect_version}"))
    else:
        out.append(_c("S02", "Версия сборки", Status.INFO, f"{apk.version_name} ({apk.version_code})"))

    # S03 — подпись
    sg = apk.signing
    if not sg.signed:
        out.append(_c("S03", "Подпись APK", Status.FAIL, "APK не подписан — не установится на устройство."))
    elif sg.schemes == ["v1"] and (apk.min_sdk or 0) >= 24:
        out.append(_c("S03", "Подпись APK", Status.WARN,
                      "Только схема v1 (JAR). Для minSdk ≥ 24 нужна v2+, иначе медленнее установка и слабее защита."))
    else:
        out.append(_c("S03", "Подпись APK", Status.PASS, "Схемы: " + ", ".join(sg.schemes)))

    # S04 — сертификат
    if sg.certs:
        cert = sg.certs[0]
        items = [f"Subject: {cert.subject}", f"SHA-256: {cert.sha256}", f"Действует до: {cert.not_after}"]
        warn_days = int(st.get("cert_expiry_warn_days", 30))
        if cert.days_left is not None and cert.days_left < 0:
            out.append(_c("S04", "Сертификат подписи", Status.FAIL, "Сертификат просрочен.", items))
        elif cert.is_debug and release:
            out.append(_c("S04", "Сертификат подписи", Status.FAIL,
                          "Release-сборка подписана отладочным ключом (CN=Android Debug).", items))
        elif cert.days_left is not None and cert.days_left < warn_days:
            out.append(_c("S04", "Сертификат подписи", Status.WARN,
                          f"Сертификат истекает через {cert.days_left} дн.", items))
        else:
            note = "отладочный ключ" if cert.is_debug else "релизный ключ"
            out.append(_c("S04", "Сертификат подписи", Status.PASS, note, items))
    elif sg.signed:
        out.append(_c("S04", "Сертификат подписи", Status.INFO,
                      sg.error or "Сертификат не извлечён (нет пакета cryptography)."))

    # S05 — debuggable
    if apk.debuggable:
        out.append(_c("S05", "android:debuggable", Status.FAIL if release else Status.INFO,
                      "debuggable=true: в release это дыра (можно подключить отладчик, читать данные)."
                      if release else "debuggable=true — ожидаемо для debug-сборки."))
    else:
        out.append(_c("S05", "android:debuggable", Status.PASS, "false"))

    # S06 — testOnly
    out.append(_c("S06", "android:testOnly", Status.FAIL if apk.test_only else Status.PASS,
                  "testOnly=true: Google Play не примет, установка только через adb install -t."
                  if apk.test_only else "false"))

    # S07 — targetSdk / minSdk
    min_target = int(st.get("min_target_sdk") or 0)
    t = apk.target_sdk or 0
    sdk_txt = f"minSdk {apk.min_sdk}, targetSdk {t}" + (f", compileSdk {apk.compile_sdk}" if apk.compile_sdk else "")
    if min_target and t < min_target:
        out.append(_c("S07", "Target SDK", Status.FAIL if release else Status.WARN,
                      f"{sdk_txt}. Google Play требует targetSdk ≥ {min_target}."))
    else:
        out.append(_c("S07", "Target SDK", Status.PASS, sdk_txt))
    floor = int(st.get("min_sdk_floor") or 0)
    if floor and (apk.min_sdk or 0) < floor:
        out.append(_c("S07b", "Min SDK", Status.WARN, f"minSdk {apk.min_sdk} ниже согласованного {floor}."))

    # S08 — открытый (cleartext) трафик
    nc = apk.network
    cleartext_default = t < 28
    cleartext = apk.uses_cleartext if apk.uses_cleartext is not None else cleartext_default
    if nc.base_cleartext is not None:
        cleartext = nc.base_cleartext
    items = []
    if nc.file:
        items.append(f"Network Security Config: {nc.file}")
    if nc.cleartext_domains:
        items.append("HTTP разрешён для: " + ", ".join(nc.cleartext_domains))
    if cleartext:
        why = ("usesCleartextTraffic=true" if apk.uses_cleartext else
               "cleartextTrafficPermitted=true" if nc.base_cleartext else f"targetSdk {t} < 28 (разрешено по умолчанию)")
        out.append(_c("S08", "Незашифрованный HTTP", Status.WARN if release else Status.INFO,
                      f"Приложению разрешён HTTP без TLS ({why}).", items))
    elif nc.cleartext_domains:
        out.append(_c("S08", "Незашифрованный HTTP", Status.WARN if release else Status.INFO,
                      "HTTP разрешён для отдельных доменов.", items))
    else:
        out.append(_c("S08", "Незашифрованный HTTP", Status.PASS, "HTTP запрещён.", items))

    # S09 — доверие пользовательским сертификатам (важно для снифинга через Charles/Proxyman)
    if nc.trusts_user_certs:
        out.append(_c("S09", "Пользовательские CA (Charles/Proxyman)", Status.WARN if release else Status.INFO,
                      "Приложение доверяет пользовательским сертификатам: трафик можно перехватить."
                      + ("" if release else " Для тестов это удобно: сниффер будет работать.")))
    else:
        out.append(_c("S09", "Пользовательские CA (Charles/Proxyman)", Status.INFO,
                      "Не доверяет пользовательским CA" + (" (кроме debug-overrides)" if nc.debug_overrides_user_certs else "")
                      + ": для перехвата трафика нужна debug-сборка с network_security_config."))

    # S10 — allowBackup
    ab = True if apk.allow_backup is None else apk.allow_backup
    out.append(_c("S10", "android:allowBackup", (Status.WARN if release else Status.INFO) if ab else Status.PASS,
                  ("true" + (" (по умолчанию)" if apk.allow_backup is None else "")
                   + ": данные приложения попадают в бэкап/adb backup. Проверьте, что там нет токенов.")
                  if ab else "false"))

    # S11 — экспортируемые компоненты
    missing = [c for c in apk.components if c.has_intent_filter and c.explicit_exported is None and c.kind != "provider"]
    if t >= 31 and missing:
        out.append(_c("S11a", "android:exported для компонентов с intent-filter", Status.FAIL,
                      "На targetSdk ≥ 31 без явного android:exported установка завершится ошибкой.",
                      [f"{c.kind}: {c.name}" for c in missing]))
    open_comps = [c for c in apk.components if c.exported and not c.permission and not c.launcher]
    if open_comps:
        out.append(_c("S11", "Экспортируемые компоненты без разрешений", Status.WARN if release else Status.INFO,
                      f"{len(open_comps)} шт. доступны другим приложениям без разрешения — кандидаты на проверку deeplink/intent.",
                      [f"{c.kind}: {c.name}" + (f"  [{', '.join(c.actions[:3])}]" if c.actions else "") for c in open_comps]))
    else:
        out.append(_c("S11", "Экспортируемые компоненты без разрешений", Status.PASS, "Нет (кроме launcher)."))

    # S12 — разрешения
    dang = apk.dangerous_permissions
    sens = apk.sensitive_permissions
    out.append(_c("S12", "Разрешения", Status.WARN if sens else Status.INFO,
                  f"Всего {len(apk.permissions)}, опасных (runtime) {len(dang)}"
                  + (f", чувствительных для Google Play {len(sens)}" if sens else ""),
                  [p.replace("android.permission.", "") + (" ⚠ runtime" if p in dang else "")
                   + (" ⚠ Play policy" if p in sens else "") for p in apk.permissions]))

    # S13 — нативные библиотеки: 64 бита и 16 KB
    nat = apk.native
    if not nat.has_native:
        out.append(_c("S13", "Нативные библиотеки / 16 KB", Status.PASS, "Нативного кода нет."))
    else:
        abis = set(nat.abis)
        problems, status = [], Status.PASS
        if ("armeabi-v7a" in abis and "arm64-v8a" not in abis) or ("x86" in abis and "x86_64" not in abis and "arm64-v8a" not in abis):
            problems.append("Нет 64-битной версии библиотек (Google Play требует arm64-v8a).")
            status = Status.FAIL
        bad = nat.not_16k()
        if bad:
            problems.append(f"{len(bad)} библиотек не выровнены под 16 KB page size "
                            "(обязательно для Google Play при targetSdk ≥ 35; на устройствах с 16 KB не запустится).")
            if status != Status.FAIL:
                status = Status.FAIL if (release and t >= 35) else Status.WARN
        out.append(_c("S13", "Нативные библиотеки / 16 KB", status,
                      "ABI: " + ", ".join(nat.abis) + (". " + " ".join(problems) if problems else ". Выравнивание 16 KB в порядке."),
                      [f"{lib.path}: p_align={lib.min_load_align}" + (", stored без выравнивания" if lib.stored and lib.zip_aligned_16k is False else "")
                       for lib in bad]))

    # S14 — секреты в коде
    high = [s for s in apk.code.secrets if s[1] == "high"]
    low = [s for s in apk.code.secrets if s[1] == "low"]
    if high:
        out.append(_c("S14", "Секреты в коде", Status.FAIL, f"Найдено {len(high)} похожих на секрет значений.",
                      [f"{n}: {v}" for n, _, v in apk.code.secrets]))
    elif low:
        out.append(_c("S14", "Секреты в коде", Status.INFO,
                      "Найдены ключи Google API — обычно это Firebase, допустимо при ограничениях в консоли.",
                      [f"{n}: {v}" for n, _, v in low]))
    else:
        out.append(_c("S14", "Секреты в коде", Status.PASS, "Явных секретов не найдено."))

    # S15 — адреса бэкендов
    ignore = {h.lower() for h in st.get("ignore_hosts", [])}
    hosts = {h: s for h, s in apk.code.urls.items() if h not in ignore and not h.endswith(".w3.org")}
    forbidden = [h for h in hosts if host_matches(h, st.get("forbidden_url_patterns", []))]
    http_hosts = [h for h, s in hosts.items() if ("http" in s or "ws" in s) and not h.startswith(LOCAL_HOSTS)
                  and not ({"https", "wss"} & s)]
    items = [f"{h}  ({', '.join(sorted(hosts[h]))})" + ("  ⚠ тестовый стенд?" if h in forbidden else "")
             + ("  ⚠ только HTTP" if h in http_hosts else "") for h in sorted(hosts)]
    if forbidden and release:
        out.append(_c("S15", "Адреса бэкендов", Status.FAIL,
                      f"В release-сборке найдены адреса тестовых стендов: {', '.join(sorted(forbidden)[:5])}", items))
    elif http_hosts:
        out.append(_c("S15", "Адреса бэкендов", Status.WARN, f"Есть адреса только по HTTP: {', '.join(sorted(http_hosts)[:5])}", items))
    else:
        out.append(_c("S15", "Адреса бэкендов", Status.INFO, f"Найдено хостов: {len(hosts)}", items))

    # S16 — отладочные библиотеки
    if apk.code.debug_libs:
        out.append(_c("S16", "Отладочные библиотеки", Status.FAIL if release else Status.INFO,
                      "В сборке есть инструменты разработчика: " + ", ".join(apk.code.debug_libs)))
    else:
        out.append(_c("S16", "Отладочные библиотеки", Status.PASS, "LeakCanary/Chucker/Flipper/Stetho не найдены."))

    # S17 — размер
    max_mb = float(st.get("max_apk_size_mb") or 0)
    if max_mb and apk.size_mb > max_mb:
        out.append(_c("S17", "Размер APK", Status.WARN, f"{apk.size_mb} МБ — больше лимита {max_mb} МБ."))
    else:
        out.append(_c("S17", "Размер APK", Status.PASS, f"{apk.size_mb} МБ"))

    # S18 — локализация
    expected_loc = [x.lower() for x in st.get("expected_locales") or []]
    if expected_loc and not apk.locales:
        out.append(_c("S18", "Локализации", Status.INFO, "В APK нет resources.arsc со строками — проверить локали нельзя."))
    elif expected_loc:
        have = {loc.split("-")[0].lower() for loc in apk.locales} | {"en"}
        miss = [x for x in expected_loc if x.split("-")[0] not in have]
        out.append(_c("S18", "Локализации", Status.WARN if miss else Status.PASS,
                      (f"Нет строк для: {', '.join(miss)}" if miss else "Все ожидаемые локали на месте")
                      + f". В сборке {len(apk.locales)} локалей."))

    out.extend(compare_builds(apk, prev, cfg))
    return apply_overrides(out, st.get("severity_overrides") or {})


def compare_builds(apk: ApkInfo, prev: dict[str, Any] | None, cfg: Config) -> list[CheckResult]:
    if not prev:
        return [_c("D00", "Сравнение с прошлой сборкой", Status.SKIP, "Это первая проверка этого пакета.")]
    out: list[CheckResult] = []
    pv = f"{prev.get('version_name')} ({prev.get('version_code')})"
    ref = f"Сравнение с {pv}"

    prev_code = prev.get("version_code") or 0
    if apk.version_code is not None and apk.version_code < prev_code:
        out.append(_c("D01", "versionCode", Status.FAIL,
                      f"{apk.version_code} меньше, чем у прошлой сборки {prev_code}: обновление поверх не установится."))
    elif apk.version_code == prev_code and apk.sha256 != prev.get("sha256"):
        out.append(_c("D01", "versionCode", Status.WARN,
                      f"versionCode не изменился ({prev_code}), а файл другой — путаница с версиями."))
    else:
        out.append(_c("D01", "versionCode", Status.PASS, f"{prev_code} → {apk.version_code}"))

    prev_certs = [c.get("sha256") for c in (prev.get("signing") or {}).get("certs", [])]
    cur_certs = [c.sha256 for c in apk.signing.certs]
    if prev_certs and cur_certs and prev_certs[0] != cur_certs[0]:
        out.append(_c("D02", "Ключ подписи", Status.FAIL,
                      "Ключ подписи изменился: обновление поверх прошлой версии не установится (INSTALL_FAILED_UPDATE_INCOMPATIBLE).",
                      [f"было: {prev_certs[0][:23]}…", f"стало: {cur_certs[0][:23]}…"]))

    prev_perms = set(prev.get("permissions") or [])
    added = sorted(set(apk.permissions) - prev_perms)
    removed = sorted(prev_perms - set(apk.permissions))
    if added or removed:
        risky = [p for p in added if p in set(apk.dangerous_permissions) | set(apk.sensitive_permissions)]
        out.append(_c("D03", "Изменения разрешений", Status.WARN if risky else Status.INFO,
                      f"{ref}: +{len(added)} / −{len(removed)}" + (". Новые опасные разрешения — нужен тест диалогов." if risky else ""),
                      [f"+ {p}" for p in added] + [f"− {p}" for p in removed]))
    else:
        out.append(_c("D03", "Изменения разрешений", Status.PASS, f"{ref}: без изменений"))

    prev_size = prev.get("size_bytes") or 0
    if prev_size:
        growth = (apk.size_bytes - prev_size) / prev_size * 100
        lim = float(cfg.get_path("static.size_growth_warn_pct", 10))
        out.append(_c("D04", "Изменение размера", Status.WARN if growth > lim else Status.PASS,
                      f"{round(prev_size / 1048576, 2)} → {apk.size_mb} МБ ({growth:+.1f}%)"))

    if prev.get("target_sdk") != apk.target_sdk:
        out.append(_c("D05", "Смена targetSdk", Status.WARN,
                      f"{prev.get('target_sdk')} → {apk.target_sdk}: меняется поведение ОС, нужен регресс разрешений, уведомлений, фоновой работы."))

    prev_exp = {c["name"] for c in prev.get("components", []) if c.get("exported")}
    cur_exp = {c.name for c in apk.components if c.exported}
    new_exp = sorted(cur_exp - prev_exp)
    if new_exp:
        out.append(_c("D06", "Новые экспортируемые компоненты", Status.INFO,
                      "Появились новые точки входа — проверить deeplink/intent.", new_exp))

    prev_hosts = set((prev.get("code") or {}).get("urls", {}).keys())
    new_hosts = sorted(set(apk.code.urls) - prev_hosts)
    if prev_hosts and new_hosts:
        out.append(_c("D07", "Новые адреса в коде", Status.INFO, f"{len(new_hosts)} новых хостов", new_hosts))

    prev_loc = set(prev.get("locales") or [])
    lost = sorted(prev_loc - set(apk.locales))
    if lost:
        out.append(_c("D08", "Пропали локализации", Status.WARN, ", ".join(lost)))
    return out


def apply_overrides(results: list[CheckResult], overrides: dict[str, str]) -> list[CheckResult]:
    if not overrides:
        return results
    for r in results:
        new = overrides.get(r.id)
        if new and r.status in (Status.FAIL, Status.WARN, Status.INFO):
            r.extra["original_status"] = r.status.value
            r.status = Status(str(new).upper())
    return results
