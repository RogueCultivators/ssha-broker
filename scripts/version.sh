#!/usr/bin/env sh
# Prints the version a package should be named after.
#
# A commit hash is not a version, and a Debian version has to begin with a
# digit, so an untagged build reports itself as 0.0.0+git<sha> rather than as a
# hash that dpkg will refuse. Tagged builds get the tag.
#
# Everything after a tag has to sort *after* it. git describe writes
# v0.2.0-9-g69facff, and nfpm turns the first "-" into "~" for Debian, where "~"
# sorts before the empty string: 0.2.0~9 would be older than 0.2.0, so a build
# made after a release would look like a downgrade. "+9.g69facff" is what Debian
# expects for a post-release snapshot, and it sorts correctly.
#
#   v1.4.0            -> 1.4.0
#   v1.4.0-9-g69facff -> 1.4.0+9.g69facff
#   v1.4.0-9-g69facff-dirty -> 1.4.0+9.g69facff.dirty
#   v1.4.0-dirty      -> 1.4.0+dirty
#   69facff           -> 0.0.0+git69facff
set -eu

pkg_version() {
  desc=$1
  case "$desc" in
    v[0-9]*)
      v=${desc#v}
      # The version keeps its dots and digits; the describe suffix is rewritten
      # so that a "-" never reaches the packager.
      case "$v" in
        *-*)
          base=${v%%-*}
          rest=${v#*-}
          # 9-g69facff-dirty -> 9.g69facff.dirty
          rest=$(printf '%s' "$rest" | tr '-' '.')
          printf '%s+%s\n' "$base" "$rest"
          ;;
        *) printf '%s\n' "$v" ;;
      esac
      ;;
    # A bare string that starts with a digit could be a hash like 1726c7e, so
    # only something with a dot counts as a version.
    [0-9]*.*) printf '%s\n' "$desc" ;;
    *) printf '0.0.0+git%s\n' "$desc" ;;
  esac
}

self_test() {
  fail=0
  check() { # check <describe> <want>
    got=$(pkg_version "$1")
    if [ "$got" != "$2" ]; then
      printf 'FAIL %-32s got %s, want %s\n' "$1" "$got" "$2" >&2
      fail=1
    fi
  }
  check v1.4.0 1.4.0
  check v1 1
  check v1.4.0-9-g69facff 1.4.0+9.g69facff
  check v1.4.0-9-g69facff-dirty 1.4.0+9.g69facff.dirty
  check v1.4.0-dirty 1.4.0+dirty
  check 69facff 0.0.0+git69facff
  check 1726c7e 0.0.0+git1726c7e
  check dev 0.0.0+gitdev
  # The point of the rewrite: a build after a tag must sort after it.
  if [ "$(printf '%s\n%s\n' "0.2.0" "$(pkg_version v0.2.0-9-g69facff)" | sort -V | tail -1)" != "0.2.0+9.g69facff" ]; then
    echo "FAIL a post-tag build does not sort after its tag" >&2
    fail=1
  fi
  # And a Debian version has to begin with a digit.
  case "$(pkg_version v0.2.0-9-g69facff)" in
    [0-9]*) ;;
    *) echo "FAIL the package version does not start with a digit" >&2; fail=1 ;;
  esac
  [ "$fail" = 0 ] && echo "version.sh: all checks passed"
  return "$fail"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

desc=$(git describe --tags --always 2>/dev/null || echo dev)
pkg_version "$desc"
