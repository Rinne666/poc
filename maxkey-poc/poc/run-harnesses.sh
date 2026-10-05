#!/usr/bin/env bash
# =============================================================================
#  run-harnesses.sh — rebuild and re-run the three Java harnesses.
#
#  ###########################################################################
#  #  THIS SCRIPT *WAS* EXECUTED BY THE AUDIT. The three harnesses it drives  #
#  #  are real runtime evidence and their output is captured under          #
#  #  harness-results/. See RESULTS.md for what each one does and does not   #
#  #  prove.                                                              #
#  ###########################################################################
#
#  WHAT THIS IS
#    A self-contained rebuild of the harnesses from the copied MaxKey sources
#    plus the local Maven cache, then a run of each. It contacts NO network and
#    needs NO running MaxKey instance.
#
#  IMPORTANT EXECUTION CONTEXT
#    These JVMs were run UNSANDBOXED. sandbox-exec cannot confine a JVM in this
#    environment — it aborts with SIGABRT — so no OS-level isolation was applied.
#    The harnesses only do string comparisons and local crypto, but the absence
#    of a sandbox is stated here rather than implied.
#
#  PREREQUISITES
#    * A JDK at the path below (or set JAVA_HOME).
#    * The jars listed in harness-lib/classpath.txt in the local Maven cache.
#
#  USAGE
#    ./run-harnesses.sh
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-/opt/homebrew/Cellar/openjdk/26.0.2.1/libexec/openjdk.jdk/Contents/Home}"
JAVAC="$JAVA_HOME/bin/javac"
JAVA="$JAVA_HOME/bin/java"

if [ ! -x "$JAVAC" ]; then
  echo "ERROR: no javac at $JAVAC"
  echo "Set JAVA_HOME to a JDK 17+ installation and re-run."
  exit 2
fi

LIB_CP="$(cat harness-lib/classpath.txt)"
# Expand the ${M2_REPO:-...} / $HOME placeholders so the file works on any machine.
eval "LIB_CP=\"$LIB_CP\""
mkdir -p harness-results

run_harness() {
  local name="$1" srcdir="$2" outdir="$3" cls="$4" extra_cp="$5" resultfile="$6"
  echo
  echo "###########################################################################"
  echo "# $name"
  echo "###########################################################################"
  mkdir -p "$outdir"
  if ! "$JAVAC" -nowarn -cp "$extra_cp" -d "$outdir" "$srcdir/$cls.java"; then
    echo "COMPILE FAILED for $cls"
    return 1
  fi
  echo "compiled OK -> $outdir"
  echo "---------------------------------------------------------------------------"
  "$JAVA" -cp "$extra_cp:$outdir" "$cls" 2>&1 | grep -v '^SLF4J'
  local rc=${PIPESTATUS[0]}
  echo "---------------------------------------------------------------------------"
  echo "exit code: $rc"
  return $rc
}

# --- shared library: MaxKey's own crypto sources, copied out of the repo ------
echo "### Building the shared library of MaxKey's own crypto classes"
mkdir -p harness-lib/out
if "$JAVAC" -nowarn -cp "$LIB_CP" -d harness-lib/out \
      $(find harness-lib -name '*.java' ! -name '*Test.java'); then
  echo "harness-lib compiled OK"
else
  echo "harness-lib COMPILE FAILED"
  exit 1
fi

RC=0

# --- Harness A: DelegatingPasswordEncoder prefix semantics --------------------
run_harness \
  "Harness A - DelegatingPasswordEncoder prefix semantics (finding 1)" \
  harness-a harness-a/out DelegatingPasswordEncoderProbe \
  "$LIB_CP:harness-lib/out" \
  harness-results/harness-A-delegating-password-encoder.txt | tee harness-results/harness-A-delegating-password-encoder.txt
[ "${PIPESTATUS[0]}" -ne 0 ] && RC=1

# --- Harness B: decipherable key inversion (finding 5) -----------------------
run_harness \
  "Harness B - decipherable column key inversion (finding 5)" \
  harness-b harness-b/out DecipherableKeyInversionProbe \
  "$LIB_CP:harness-lib/out" \
  harness-results/harness-B-decipherable-inversion.txt | tee harness-results/harness-B-decipherable-inversion.txt
[ "${PIPESTATUS[0]}" -ne 0 ] && RC=1

# --- Harness C: OAuth2 redirect prefix semantics -----------------------------
# spring-core comes from the same portable classpath as the other harnesses.
CORE_JAR="$(printf '%s' "$LIB_CP" | tr ':' '\n' | grep 'spring-core' | head -1)"
if [ -f "$CORE_JAR" ]; then
  run_harness \
    "Harness C - OAuth2 redirect_uri prefix matching (supports redirect finding)" \
    harness-c harness-c/out RedirectPrefixProbe \
    "$CORE_JAR" \
    harness-results/harness-C-redirect-prefix.txt | tee harness-results/harness-C-redirect-prefix.txt
  [ "${PIPESTATUS[0]}" -ne 0 ] && RC=1
else
  echo
  echo "SKIPPING Harness C: spring-core jar not found at $CORE_JAR"
  RC=1
fi

echo
echo "=============================================================================="
if [ "$RC" -eq 0 ]; then
  echo " ALL HARNESSES COMPILED AND PASSED. Output saved under harness-results/."
else
  echo " AT LEAST ONE HARNESS FAILED. See the output above and RESULTS.md."
fi
echo " Reminder: these JVMs ran UNSANDBOXED (sandbox-exec cannot confine a JVM here)."
echo "=============================================================================="
exit $RC
