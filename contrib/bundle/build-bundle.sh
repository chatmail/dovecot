#!/bin/bash
# Build a self-contained Dovecot bundle (proof of concept).
#
# Scope: dovecot core + imap + lmtp, built dynamically. dlopen stays
# load-bearing because the chatmail relay config loads lua plus the
# zlib/quota/last_login/notify/push_notification plugins at runtime, so a
# static build is not an option. After install, the non-glibc shared-library
# closure is copied next to the binaries and every ELF's RPATH is rewritten to
# $ORIGIN, so the tree carries its own libs and does not depend on the host's
# dovecot or matching system libraries.
#
# Relocation note: the dovecot master execs a compiled-in BINDIR/doveconf with
# no runtime override, so the bundle is installed at a FIXED prefix
# (/opt/dovecot). libexec_dir and mail_plugin_dir are overridden at runtime by
# the launcher. Arbitrary-path relocation would need a source patch and is out
# of scope for this PoC.
#
# See doc/plans/260721-01-dovecot-bundle-poc.md.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../.." && pwd)          # repo root (dovecot source tree)
prefix=${PREFIX:-/opt/dovecot}          # fixed install/run prefix
out=${OUT:-$prefix}                     # bundle root (install target)
jobs=${JOBS:-$(nproc)}

echo "== configure (core + imap + lmtp; lua + compression kept) =="
cd "$src"
if [ "${RECONFIGURE:-0}" = 1 ] || [ ! -f config.status ]; then
  ./configure \
    --disable-maintainer-mode \
    --prefix="$prefix" \
    --with-ssl=openssl \
    --with-ioloop=best \
    --with-lz4 \
    --with-sodium \
    --with-lua=plugin \
    --without-pam \
    --without-icu \
    --without-lucene \
    --without-libwrap \
    --without-apparmor \
    --without-pgsql --without-mysql --without-sqlite \
    --without-ldap --without-gssapi --without-solr \
    --disable-rpath \
    --disable-static
fi

echo "== build =="
make -j"$jobs"

echo "== install to $out =="
rm -rf "$out"
make -j"$jobs" install DESTDIR="${DESTDIR:-}"
# When DESTDIR is empty this installs straight into $prefix. Pigeonhole/sieve is
# not built (its subtree is configured separately in the deb build; excluded
# here on purpose).

# Drop build-time-only artifacts.
rm -rf "$out/include" "$out/lib/pkgconfig"
find "$out" -name '*.la' -delete 2>/dev/null || true

extdir="$out/extlib"
libdir="$out/lib/dovecot"
mkdir -p "$extdir"

is_glibc() {
  case "$1" in
    libc.so.*|libm.so.*|libdl.so.*|libpthread.so.*|librt.so.*|libresolv.so.*|\
    libnsl.so.*|libutil.so.*|libgcc_s.so.*|libanl.so.*|ld-linux*|linux-vdso*) return 0;;
    *) return 1;;
  esac
}

# Emit (NUL-separated) every ELF in the bundle except the ones already in extlib.
elf_files() {
  find "$out" -type f ! -path "$extdir/*" \
       \( -perm -u+x -o -name '*.so' -o -name '*.so.*' \) -print0 |
  while IFS= read -r -d '' f; do
    case "$(file -b "$f" 2>/dev/null)" in
      ELF*) printf '%s\0' "$f";;
    esac
  done
}

echo "== collect non-glibc shared-library closure into extlib/ =="
# ldd resolves the FULL transitive closure per file, so one pass over every
# binary and module captures dep-of-dep libs (libssl -> libcrypto, etc.).
{ while IFS= read -r -d '' f; do ldd "$f" 2>/dev/null || true; done < <(elf_files); } |
  sed -n 's/.*=> \(\/[^ ]*\) (0x.*/\1/p' | sort -u |
  while IFS= read -r path; do
    base=$(basename "$path")
    is_glibc "$base" && continue
    case "$path" in "$out"/*) continue;; esac   # dovecot's own libs stay put
    [ -e "$extdir/$base" ] || cp -L "$path" "$extdir/$base"
  done

echo "== rewrite RPATHs to \$ORIGIN =="
# Every directory in the bundle that holds shared objects: lib/dovecot itself,
# each of its module subdirs, and extlib. Some internal libs are installed into
# a subdir yet linked as a direct DT_NEEDED of a binary rather than dlopened,
# e.g. libstats_auth.so lives in lib/dovecot/old-stats but the auth binary links
# it (src/auth/Makefile.am). So each ELF's RPATH must search all of these dirs,
# not just lib/dovecot, or the loader fails with "cannot open shared object".
mapfile -t sodirs < <(
  { printf '%s\n' "$libdir" "$extdir"
    find "$libdir" -type f \( -name '*.so' -o -name '*.so.*' \) -printf '%h\n'
  } | sort -u
)
# Binaries and modules: search dovecot's own lib dirs plus extlib, all relative.
while IFS= read -r -d '' f; do
  d=$(dirname "$f")
  rp=""
  for sd in "${sodirs[@]}"; do
    rel=$(realpath --relative-to="$d" "$sd")
    rp="${rp:+$rp:}\$ORIGIN/$rel"
  done
  patchelf --set-rpath "$rp" "$f" 2>/dev/null || true
done < <(elf_files)
# Bundled third-party libs only need their siblings in the same dir.
for f in "$extdir"/*; do
  [ -f "$f" ] || continue
  patchelf --set-rpath '$ORIGIN' "$f" 2>/dev/null || true
done

# Install the relocatable launcher at the bundle root.
install -m 0755 "$here/dovecot-bundle" "$out/dovecot-bundle"

echo "== summary =="
echo "bundle:   $out"
echo "binaries: $(find "$out"/sbin "$out"/bin "$out"/libexec -type f 2>/dev/null | wc -l)"
echo "modules:  $(find "$libdir/modules" -name '*.so' 2>/dev/null | wc -l)"
echo "extlibs:  $(find "$extdir" -type f | wc -l) ($(ls "$extdir" | tr '\n' ' '))"
echo "sanity (dovecot --version, via launcher):"
"$out/dovecot-bundle" --version || true
