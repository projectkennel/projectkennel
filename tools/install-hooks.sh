#!/bin/sh
# Project Kennel git-hook installer (CODING-STANDARDS.md §15.1).
#
# Symlinks .git/hooks/<name> -> tools/git-hooks/<name> for each hook. Symlinks
# (not copies) mean updates to the committed scripts take effect on the next
# commit without re-running this. Installation is opt-in: cloning the repo does
# NOT install hooks; a checkout should never be live-fire. Read the hook scripts
# before running this.
#
# POSIX sh; no bashisms.
set -eu

hooks="pre-commit commit-msg pre-push"

repo_root="$(git rev-parse --show-toplevel)"
git_dir="$(git rev-parse --git-dir)"
# Resolve git_dir to an absolute path (it may be relative to the cwd).
case "$git_dir" in
/*) ;;
*) git_dir="$(cd "$git_dir" && pwd)" ;;
esac

src_dir="$repo_root/tools/git-hooks"
dst_dir="$git_dir/hooks"
mkdir -p "$dst_dir"

for name in $hooks; do
	src="$src_dir/$name"
	dst="$dst_dir/$name"
	if [ ! -f "$src" ]; then
		echo "install-hooks: missing $src" >&2
		exit 1
	fi
	if [ -e "$dst" ] && [ ! -L "$dst" ]; then
		echo "install-hooks: $dst exists and is not a symlink; leaving it alone" >&2
		echo "  (remove it yourself if you want the Kennel hook)" >&2
		continue
	fi
	ln -sf "$src" "$dst"
	echo "installed $name -> $src"
done

echo "Done. Hooks are convenience checks; the authoritative gate is CI (§14)."
