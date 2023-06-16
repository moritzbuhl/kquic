#!/usr/bin/bash

set -eux

TEMPDIR=$(mktemp -d)
CURRENT=$(mktemp)
SUBDIR=ngtcp2
REPO=~/quic-kernel
REPO_BASECOMMIT=507e7934da86d253f5114ac36db10de76c8db38f
NGTCP2_BASECOMMIT=f674ecda454be77798f8cbb05f9e8948bac6497c

cd $TEMPDIR
mkdir patches

git clone https://github.com/ngtcp2/ngtcp2
cd $TEMPDIR/ngtcp2
FILTER_BRANCH_SQUELCH_WARNING=1 \
	git filter-branch -f --prune-empty --subdirectory-filter lib/

git format-patch --output-directory "$TEMPDIR/patches" \
	--root $NGTCP2_BASECOMMIT
mv $TEMPDIR/patches/0001-Add-autotools-files.patch \
	$TEMPDIR/patches/0000-Init.patch
git format-patch --output-directory "$TEMPDIR/patches" $NGTCP2_BASECOMMIT..

cd $REPO
git checkout $REPO_BASECOMMIT

undo_reapply() {
	git checkout -- .
	for f in $(find . -name '*.rej'); do
		patch -R --no-backup-if-mismatch -d $SUBDIR < $f
		rm $f
	done
	patch --no-backup-if-mismatch -d $SUBDIR -p 1 < $CURRENT
}

apply_mangled_patch() {
	git am --directory=$SUBDIR --show-current-patch=diff > $CURRENT
	patch --no-backup-if-mismatch -d $SUBDIR -p 1 < $CURRENT || undo_reapply
	git add ngtcp2
	git am --continue
}

for f in $TEMPDIR/patches/*; do
	git am --directory=$SUBDIR $f || apply_mangled_patch
done
