#!/usr/bin/env bash
set -euo pipefail

# Backward compatible: input.ipa YTKACE.dylib output.ipa [extra.dylib ...]
if [[ $# -lt 2 ]]; then
  echo 'usage: sideload-repack.sh input.ipa YTKACE.dylib [output.ipa] [extra.dylib ...]' >&2
  exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$1")"
YTKACE="$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$2")"
shift 2
OUTPUT="$PWD/YTKACE_YouTube.ipa"
if [[ $# -gt 0 && "$1" == *.ipa ]]; then
  OUTPUT="$1"
  shift
fi
OUTPUT="$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$OUTPUT")"
DYLIBS=("$YTKACE")
while [[ $# -gt 0 ]]; do
  DYLIBS+=("$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$1")")
  shift
done
command -v unzip >/dev/null
command -v zip >/dev/null
command -v python3 >/dev/null
test -f "$INPUT"
for lib in "${DYLIBS[@]}"; do test -f "$lib"; done
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unzip -q "$INPUT" -d "$WORK"
APP="$(find "$WORK/Payload" -mindepth 1 -maxdepth 1 -type d -name '*.app' -print -quit)"
test -n "$APP"
case "$(cd "$APP" && pwd)" in "$WORK"/*) ;; *) echo 'invalid app path' >&2; exit 1;; esac
EXECUTABLE="$(python3 - "$APP/Info.plist" <<'PY'
import plistlib,sys
with open(sys.argv[1], 'rb') as f:
    print(plistlib.load(f)['CFBundleExecutable'])
PY
)"
MAIN="$APP/$EXECUTABLE"
test -f "$MAIN"
rm -rf "$APP/YTKACE.bundle" "$APP/Extensions/AppMigrationExtension.appex" "$APP/_CodeSignature"
find "$APP" -maxdepth 1 -type f \( -name 'YTK@*' -o -name 'YTK-*' \) -delete
python3 "$ROOT/Tools/sanitize_plist.py" "$APP/Info.plist"
mkdir -p "$APP/Frameworks"
# Inject every library into the SAME app before signing and repacking.
# Reject duplicate basenames: an overwrite would silently lose a tweak.
for lib in "${DYLIBS[@]}"; do
  name="$(basename "$lib")"
  # No empty arrays: compatible with macOS Bash 3.2 and set -u.
  if [[ -e "$APP/Frameworks/$name" ]]; then
    echo "Duplicate or existing library name: $name" >&2
    exit 1
  fi
  cp "$lib" "$APP/Frameworks/$name"
  python3 "$ROOT/Tools/macho_inject.py" "$MAIN" --add-load "@rpath/$name"
done
cp -R "$ROOT/Resources/YTKACE.bundle" "$APP/YTKACE.bundle"
# Sign once, after all injection operations.
bash "$ROOT/Scripts/sign-bundle.sh" "$APP"
mkdir -p "$(dirname "$OUTPUT")"
ARCHIVE="$WORK/combined.ipa"
(cd "$WORK" && zip -qry "$ARCHIVE" Payload)
mv -f "$ARCHIVE" "$OUTPUT"
python3 - "$OUTPUT" "${DYLIBS[@]}" <<'PY'
import pathlib,sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    names=set(z.namelist())
    for p in sys.argv[2:]:
        target=pathlib.Path(p).name
        assert any(n.endswith('/Frameworks/'+target) for n in names),f'Missing: {target}'
print('Verified libraries:',', '.join(pathlib.Path(p).name for p in sys.argv[2:]))
PY
echo "$OUTPUT"
