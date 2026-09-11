#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p work/lib work/classes work/test-classes build
fetch() {
  local path="$1" dest="work/lib/${1##*/}"
  if [ ! -f "$dest" ]; then
    curl --connect-timeout 10 --max-time 45 --retry 2 --fail --location --silent --show-error "https://repo.maven.apache.org/maven2/$path" -o "$dest.tmp"
    mv "$dest.tmp" "$dest"
  fi
  if [ ! -f "$dest.sha256" ]; then
    curl --connect-timeout 10 --max-time 45 --retry 2 --fail --location --silent --show-error "https://repo.maven.apache.org/maven2/$path.sha256" -o "$dest.sha256.tmp"
    mv "$dest.sha256.tmp" "$dest.sha256"
  fi
  python3 - "$dest" "$dest.sha256" <<'PY'
import hashlib, pathlib, sys
p, checksum = map(pathlib.Path, sys.argv[1:])
assert hashlib.sha256(p.read_bytes()).hexdigest() == checksum.read_text().strip().split()[0], f'Checksum mismatch: {p}'
PY
}
fetch net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar
fetch com/google/code/gson/gson/2.14.0/gson-2.14.0.jar
CP="work/lib/montoya-api-2026.7.jar:work/lib/gson-2.14.0.jar"
# Remove stale compiled classes without touching source or captures.
find work/classes work/test-classes -type f -delete
javac --release 17 -cp "$CP" -d work/classes src/main/java/interactshbridge/*.java
javac --release 17 -cp "$CP:work/classes" -d work/test-classes src/test/java/interactshbridge/*.java
java -Djava.awt.headless=true -cp "$CP:work/classes:work/test-classes" interactshbridge.BridgeTests
(cd work/classes && jar xf ../lib/gson-2.14.0.jar)
cp -R src/main/resources/. work/classes/
# Burp supplies Montoya; only bundle our classes and Gson.
jar --create --file build/Interactsh-Bridge.jar -C work/classes .
echo "Built build/Interactsh-Bridge.jar"
