#!/bin/bash
# macOS: двойной клик спросит путь к APK; или из терминала: ./scripts/check_apk.command app.apk
cd "$(dirname "$0")/.." || exit 1
APK="$1"
if [ -z "$APK" ]; then
  read -r -p "Перетащите APK в это окно и нажмите Enter: " APK
  APK="${APK//\\ / }"; APK="${APK%\"}"; APK="${APK#\"}"; APK="${APK%\'}"; APK="${APK#\'}"; APK="$(echo "$APK" | xargs)"
fi
qa check "$APK" --open --fail-on never
