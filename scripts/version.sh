#!/usr/bin/env sh
# Prints the version a package should be named after.
#
# A commit hash is not a version, and a Debian version has to begin with a
# digit, so an untagged build reports itself as 0.0.0+git<sha> rather than as a
# hash that dpkg will refuse. Tagged builds get the tag.
set -eu

desc=$(git describe --tags --always 2>/dev/null || echo dev)
# v<digit> is a tag, so it counts even without a dot. A bare string that starts
# with a digit could be a hash like 1726c7e, so that one has to have a dot too:
# this is the same rule as version.IsVersion in internal/version.
case "$desc" in
  v[0-9]*) printf '%s\n' "${desc#v}" ;;
  [0-9]*.*) printf '%s\n' "$desc" ;;
  *) printf '0.0.0+git%s\n' "$desc" ;;
esac
