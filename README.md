# qa-tool: автоматическая приёмка Android-сборок

Тестировщик получает APK и запускает одну команду, дальше всё делается без него:

```
qa check app-release.apk
```

```text
APK ─┬─► Статический анализ (без устройства, ~1 с)
     │     пакет, версия, подпись, SDK, debuggable, cleartext, 16 KB, секреты,
     │     адреса стендов, отладочные библиотеки, экспортируемые компоненты
     │     + сравнение с прошлой проверенной сборкой (разрешения, размер, ключ, versionCode)
     │
     ├─► Эмулятор (базовая проверка, тесты писать не нужно)
     │     чистая установка → холодный старт ×3 → «жив ли процесс» → скриншот → память
     │     → Maestro-флоу (если есть) → monkey-стресс → крэши/ANR из logcat
     │
     └─► Вердикт: Принять / Принять с замечаниями / Не принимать
           HTML-отчёт (одним файлом) · история · Google Таблица · Telegram
```

Попробовать без эмулятора и без своего APK можно так: `qa demo --open`. Команда соберёт две версии выдуманного приложения и покажет отчёт с найденными проблемами.

---

## Установка (один раз)

Нужно:
- **Python 3.10+**;
- **Android Studio** с эмулятором или отдельные platform-tools. Команда `adb` должна запускаться из терминала;
- *необязательно:* **Maestro** для сценариев. Ему нужна Java 17+.

```bash
# в папке проекта
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -e ".[sheets]"

qa init .          # создаст qa.yaml и примеры флоу, если их нет
qa doctor          # проверит: adb, эмулятор, Maestro, Java, доступ к Google Таблице
```

Maestro (macOS/Linux/WSL): `curl -fsSL "https://get.maestro.mobile.dev" | bash`. Установка на Windows описана в [документации Maestro](https://docs.maestro.dev/).

## Ежедневная работа

1. Запустите эмулятор: Android Studio → Device Manager → ▶.
2. Проверьте сборку:

```bash
qa check ~/Downloads/app-release-1.5.0.apk --open
```

На Windows можно просто **перетащить APK на `scripts\check_apk.bat`**. На macOS для этого есть `scripts/check_apk.command`.

| Команда | Что делает |
|---|---|
| `qa check app.apk` | полная проверка: статика, эмулятор, Maestro, monkey, отчёт |
| `qa static app.apk` | только анализ файла, без устройства (несколько секунд) |
| `qa check app.apk --expect-version 1.5.0` | ещё и сверит версию с ожидаемой |
| `qa check app.apk --build-type debug` | мягкие правила для debug-сборки |
| `qa check app.apk -d emulator-5556` | выбрать конкретное устройство |
| `qa check app.apk --skip-maestro --no-monkey` | быстрый прогон: установка, старт, крэши |
| `qa check app.apk --sheets` / `--telegram` | выгрузить в Google Таблицу или отправить в Telegram |
| `qa history` | история прогонов в терминале |
| `qa report qa_runs/<прогон>` | пересобрать HTML-отчёт |
| `qa doctor [--online]` | диагностика окружения |
| `qa demo --open` | демо-отчёт |

Код выхода (пригодится для CI): `0` — принято, `2` — «Не принимать», `3` — ошибка входных данных. Флаг `--fail-on remarks` вернёт `1` и на «С замечаниями».

## Что лежит в папке прогона

```
qa_runs/
  history.csv                                  ← все прогоны, открывается в Excel
  20261009-154210_com.demo.shop_1.5.0/
    report.html        ← главный отчёт (скриншоты вшиты, можно переслать одним файлом)
    summary.json       ← всё в машинно-читаемом виде
    junit_all.xml      ← все проверки как JUnit (для GitLab/Jenkins)
    apk_info.json      ← полный разбор APK
    device/logcat.txt  ← logcat за весь прогон
    device/screens/    ← скриншоты после старта и после monkey
    device/monkey.txt
    maestro/           ← junit.xml, вывод и скриншоты Maestro
```

## Настройка: `qa.yaml`

Все параметры с комментариями собраны в [`qa.yaml`](qa.yaml). Первым делом заполните:

```yaml
project:
  name: "Мой магазин"
  expected_app_id: "ru.company.shop"   # поймает «не тот флейвор»
  build_type: release
static:
  expected_locales: [ru, en]
  forbidden_url_patterns: [staging, dev., test., localhost]
```

Если какая-то проверка у вас осознанно «красная», понизьте её статус: `static.severity_overrides: {S10: INFO}`.

Описание каждой проверки и её логики: [docs/CHECKS.md](docs/CHECKS.md).

## Сценарии Maestro

Флоу лежат в `.maestro/smoke/`. Метаданные из флоу попадают в отчёт и таблицу:

```yaml
appId: ${MAESTRO_APP_ID}        # подставляется из APK автоматически
name: SMOKE-002 Логин
tags: [smoke]
properties:
  testCaseId: "SMOKE-002"       # ID из вашей TMS
  priority: "P0"                # упал P0 → «Не принимать»; P1/P2 → «с замечаниями»
---
- launchApp:
    clearState: true
- tapOn: "Войти"
- inputText: ${LOGIN}           # из qa.yaml → maestro.env → .env
```

Упавший флоу перезапускается (`maestro.retries`). Если со второй попытки он прошёл, в отчёте он помечается как «Нестабилен», а не как баг. Скриншоты падения Maestro привязываются к тесту в отчёте. Если Maestro не установлен или флоу нет, выполняется только базовая проверка, и вердикт всё равно выносится.

## Google Таблица

Каждый прогон добавляет строку на лист «Прогоны», а все проверки этого прогона идут строками на лист «Проверки». По ним удобно строить графики и искать, что падает чаще всего. Настройка займёт 5 минут: [docs/GOOGLE_SHEETS.md](docs/GOOGLE_SHEETS.md).

## Разработка

```bash
pip install -e ".[sheets,dev]"
pytest                    # 21 тест; adb и Maestro подменяются фейками из tests/fake_bin
QA_REAL_APKS=a.apk:b.apk pytest tests/test_apk.py   # прогнать парсер на реальных сборках
```

Структура:

```
qa_tool/
  apk/          разбор APK без внешних утилит: AndroidManifest (AXML), resources.arsc,
                подпись v1/v2/v3, ELF (16 KB), строки DEX
  static_checks.py   проверки S01–S18 и сравнение со сборкой D01–D08
  device/       adb, базовая проверка на устройстве, разбор logcat/monkey
  maestro.py    запуск флоу, JUnit, метаданные, доказательства, flaky
  verdict.py    правила вердикта
  report/       HTML-отчёт (Jinja2)
  integrations/ Google Sheets, Telegram
  pipeline.py   оркестратор
  cli.py        команды qa …
```

Что дальше по плану: [docs/ROADMAP.md](docs/ROADMAP.md).

> Автоматическая проверка не заменяет исследовательское тестирование. Её задача — убрать рутину до того, как тестировщик возьмёт сборку в руки.
