#!/bin/bash
# Build script for the Kakeibo Android app in this VM.
# Usage: ./build.sh [gradle tasks...]   (default: :app:testDebugUnitTest :app:assembleDebug)
set -u
export JAVA_HOME=$HOME/workspace/.tools/jdk
export ANDROID_HOME=$HOME/workspace/.tools/android-sdk
export ANDROID_SDK_ROOT=$ANDROID_HOME
export GRADLE_USER_HOME=$HOME/.gradle
export PATH=$JAVA_HOME/bin:$HOME/workspace/.tools/gradle-dist/gradle-9.3.1/bin:$PATH

# 1) Kill stale gradle daemons
python3 - << 'PYEOF'
import os, signal
for pid in os.listdir("/proc"):
    if pid.isdigit():
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read().decode("utf-8", "ignore")
            if "GradleDaemon" in cmd:
                os.kill(int(pid), signal.SIGKILL); print("killed", pid)
        except Exception:
            pass
PYEOF
sleep 1

# 2) Gradle proxy config (creds parsed from env, never printed)
python3 - << 'PYEOF'
import os, urllib.parse
proxy_url = None
try:
    raw = open("/proc/self/environ", "rb").read().decode("utf-8", "ignore")
    for entry in raw.split("\0"):
        for key in ("https_proxy=", "HTTPS_PROXY=", "http_proxy="):
            if entry.startswith(key) and "@" in entry:
                proxy_url = entry[len(key):]
                break
        if proxy_url:
            break
except Exception:
    pass
if not proxy_url:
    for k, v in os.environ.items():
        if "proxy" in k.lower() and "@" in v:
            proxy_url = v; break
u = urllib.parse.urlparse(proxy_url)
os.makedirs(os.path.expanduser("~/.gradle"), exist_ok=True)
with open(os.path.expanduser("~/.gradle/gradle.properties"), "w") as f:
    f.write(f"systemProp.http.proxyHost={u.hostname}\n")
    f.write(f"systemProp.http.proxyPort={u.port}\n")
    f.write(f"systemProp.http.proxyUser={urllib.parse.unquote(u.username or '')}\n")
    f.write(f"systemProp.http.proxyPassword={urllib.parse.unquote(u.password or '')}\n")
    f.write(f"systemProp.https.proxyHost={u.hostname}\n")
    f.write(f"systemProp.https.proxyPort={u.port}\n")
    f.write(f"systemProp.https.proxyUser={urllib.parse.unquote(u.username or '')}\n")
    f.write(f"systemProp.https.proxyPassword={urllib.parse.unquote(u.password or '')}\n")
    f.write("systemProp.http.nonProxyHosts=localhost|127.0.0.1\n")
    f.write("systemProp.https.nonProxyHosts=localhost|127.0.0.1\n")
print("gradle proxy config written for host", u.hostname, "port", u.port)
PYEOF

# 3) Truststore (JDK cacerts + Hatch Sandbox Egress CA) - rebuilt every run
# because the egress CA rotates and a stale truststore causes PKIX failures.
TS=$HOME/workspace/.tools/truststore.jks
if true; then
  python3 - << 'PYEOF'
import re, subprocess
data = open("/run/hatch/egress-tls/ca-bundle.pem").read()
blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
for i, b in enumerate(blocks):
    p = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer"], input=b.encode(), capture_output=True)
    if "Hatch" in p.stdout.decode():
        open("/tmp/hatch-ca.pem", "w").write(b + "\n")
        break
PYEOF
  cp $JAVA_HOME/lib/security/cacerts "$TS"
  $JAVA_HOME/bin/keytool -importcert -noprompt -trustcacerts -alias hatch-egress-ca -file /tmp/hatch-ca.pem -keystore "$TS" -storepass changeit 2>&1 | tail -n 1
fi

export JAVA_TOOL_OPTIONS="-Djava.net.preferIPv4Stack=true -Djavax.net.ssl.trustStore=$TS -Djavax.net.ssl.trustStorePassword=changeit"
export GRADLE_OPTS="-Xmx2g -Dfile.encoding=UTF-8"

cd "$(dirname "$0")" || exit 1
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > local.properties

TASKS=("$@")
if [ ${#TASKS[@]} -eq 0 ]; then
  TASKS=(:app:testDebugUnitTest :app:assembleDebug)
fi
echo "=== gradle ${TASKS[*]} ==="
gradle "${TASKS[@]}" --no-configuration-cache -Dorg.gradle.java.installations.auto-download=false 2>&1 | tail -n 40
echo "=== outputs ==="
ls -lh app/build/outputs/apk/debug/ 2>/dev/null
