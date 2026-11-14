#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: sign-bundle.sh YouTube.app" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$(cd "$1" && pwd)"
LDID="${LDID:-ldid}"
if ! command -v "$LDID" >/dev/null 2>&1; then
  for candidate in \
    "${THEOS:-$HOME/theos}/toolchain/linux/iphone/bin/ldid" \
    "$HOME/theos/toolchain/linux/iphone/bin/ldid"; do
    if [[ -x "$candidate" ]]; then
      LDID="$candidate"
      break
    fi
  done
fi

command -v "$LDID" >/dev/null 2>&1 || { echo "ERROR: ldid not found" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found" >&2; exit 1; }

EXECUTABLE="$(python3 - "$APP/Info.plist" <<'PY'
import plistlib
import sys
with open(sys.argv[1], 'rb') as f:
    print(plistlib.load(f)['CFBundleExecutable'])
PY
)"
MAIN="$APP/$EXECUTABLE"
test -f "$MAIN" || { echo "ERROR: executable not found: $MAIN" >&2; exit 1; }

ENTITLEMENTS="$(mktemp)"
TARGETS="$(mktemp)"
trap 'rm -f "$ENTITLEMENTS" "$TARGETS"' EXIT

# Read all candidate paths first, and classify their Mach-O file types before
# invoking ldid. ldid cannot sign MH_OBJECT/MH_FILESET and can abort abruptly.
python3 - "$ROOT/Tools/list_macho.py" "$APP" "$MAIN" >"$TARGETS" <<'PY'
import os
import struct
import subprocess
import sys

scanner, app, main = sys.argv[1:]
main = os.path.realpath(main)
allowed = {2, 6, 7, 8}  # MH_EXECUTE, MH_DYLIB, MH_DYLINKER, MH_BUNDLE
names = {1:'MH_OBJECT', 2:'MH_EXECUTE', 6:'MH_DYLIB',
         7:'MH_DYLINKER', 8:'MH_BUNDLE', 12:'MH_FILESET'}

# Magic as on-disk bytes; the 32/64-bit Mach-O filetype is at offset 12.
thin_magic = {
    b'\xfe\xed\xfa\xce': '>', b'\xce\xfa\xed\xfe': '<',
    b'\xfe\xed\xfa\xcf': '>', b'\xcf\xfa\xed\xfe': '<',
}
fat_magic = {
    b'\xca\xfe\xba\xbe': ('>', 20), b'\xbe\xba\xfe\xca': ('<', 20),
    b'\xca\xfe\xba\xbf': ('>', 24), b'\xbf\xba\xfe\xca': ('<', 24),
}

def filetypes(f, offset=0, depth=0):
    if depth > 2:
        raise ValueError('too many nested fat headers')
    f.seek(offset)
    magic = f.read(4)
    if magic in thin_magic:
        f.seek(offset + 12)
        field = f.read(4)
        if len(field) != 4:
            raise ValueError('truncated Mach-O header')
        return [struct.unpack(thin_magic[magic] + 'I', field)[0]]
    if magic in fat_magic:
        endian, entry_size = fat_magic[magic]
        count_raw = f.read(4)
        if len(count_raw) != 4:
            raise ValueError('truncated fat header')
        count = struct.unpack(endian + 'I', count_raw)[0]
        if not 1 <= count <= 64:
            raise ValueError('invalid fat architecture count')
        types = []
        for i in range(count):
            f.seek(offset + 8 + i * entry_size)
            entry = f.read(entry_size)
            if len(entry) != entry_size:
                raise ValueError('truncated fat architecture table')
            # 2 x uint32 (cpu), followed by a uint32/uint64 slice offset.
            fmt = endian + ('Q' if entry_size == 24 else 'I')
            slice_offset = struct.unpack_from(fmt, entry, 8)[0]
            types.extend(filetypes(f, offset + slice_offset, depth + 1))
        return types
    return []

try:
    output = subprocess.check_output([sys.executable, scanner, app], text=True)
except subprocess.CalledProcessError as exc:
    sys.exit(f'ERROR: list_macho.py failed: {exc}')

seen = set()
for line in [main, *output.splitlines()]:
    path = os.path.realpath(line.strip())
    if not path or path in seen:
        continue
    seen.add(path)
    if not os.path.isfile(path):
        sys.exit(f'ERROR: missing signing candidate: {path}')
    try:
        with open(path, 'rb') as f:
            types = filetypes(f)
    except (OSError, ValueError, struct.error) as exc:
        sys.exit(f'ERROR: cannot parse {path}: {exc}')
    if types and all(t in allowed for t in types):
        sys.stderr.write(f'SIGN TARGET: {path} (types: {types})\n')
        if path != main:
            sys.stdout.buffer.write(os.fsencode(path) + b'\0')
    else:
        detail = ', '.join(names.get(t, f'type {t}') for t in types) if types else 'not Mach-O'
        # A broken injected dylib or app executable must not silently pass.
        if path == main or path.lower().endswith('.dylib'):
            sys.exit(f'ERROR: unsupported required binary: {path} ({detail})')
        sys.stderr.write(f'SKIP (not signable): {path} ({detail})\n')

# Emit main last; the script reads all other targets and signs main separately.
PY

# Keep existing main executable entitlements when ldid can extract them.
"$LDID" -e "$MAIN" >"$ENTITLEMENTS" 2>/dev/null || true

while IFS= read -r -d '' binary; do
  echo "Signing: $binary"
  if ! "$LDID" -S "$binary"; then
    echo "ERROR: ldid failed while signing: $binary" >&2
    exit 1
  fi
done <"$TARGETS"

echo "Signing main executable: $MAIN"
if [[ -s "$ENTITLEMENTS" ]]; then
  if ! "$LDID" "-S$ENTITLEMENTS" "$MAIN"; then
    echo "ERROR: ldid failed while signing main executable: $MAIN" >&2
    exit 1
  fi
else
  if ! "$LDID" -S "$MAIN"; then
    echo "ERROR: ldid failed while signing main executable: $MAIN" >&2
    exit 1
  fi
fi

echo "Finished signing bundle: $APP"
