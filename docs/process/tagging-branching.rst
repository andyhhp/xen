.. SPDX-License-Identifier: CC-BY-4.0

===============================
Tagging and Branching Checklist
===============================

Before starting
===============

 * Review this checklist for changes during the development window.
 * Access to the following necessary:

   * The 'xen tree' signing key.
   * The xen and xendocs users on xenbits.xen.org
   * The downloads-cvs user on mail.xenproject.org
   * A checkout of the xen.org CVS repository

::

  cvs -d downloads-cvs@mail.xenproject.org:/home/downloads-cvs/cvs-repos checkout xen.org


For RC1
=======

 * Pin ``QEMU_UPSTREAM_REVISION`` to an exact SHA.  Commit.

 * Update ``XEN_EXTRAVERSION`` from ``-unstable`` to ``.0-rc1``.  For
   ``README`` and ``SUPPORT.md``, use the slightly more generic ``-rc`` so
   they doesn't need to change during subsequent RCs.  Commit.

 * Tag.  Produce tarballs.

e.g. from Xen 4.21, ``ffd25d717a74^..d1478321eacb``::

  * d1478321eacb - (tag: 4.21.0-rc1) Update Xen version to 4.21.0-rc1
  * ffd25d717a74 - Config.mk: Pin QEMU_UPSTREAM_REVISION


For subsequent RCs
==================

 * Update ``XEN_EXTRAVERSION`` to the next RC number.  Commit.  Tag.

e.g. from Xen 4.21, ``eff32008be0d`` and ``9632ce6fe5b2``::

  * 9632ce6fe5b2 - (tag: 4.21.0-rc3) Update Xen version to 4.21.0-rc3
  * eff32008be0d - (tag: 4.21.0-rc2) Update Xen version to 4.21.0-rc2


Branching
=========

On xenbits:

 * Create new staging and stable branches in xen.git.

 * Add the new branches to patchbot.  In ``~xen/HG/patchbot`` copy the exsting
   master and staging reported heads, update the ``versions`` file, and commit
   the result.

 * Add the new stable branch to the docs cronjob.  In ``~xendocs/cronjobs``
   edit ``xenbits-docs-all.sh`` and commit the result.  e.g.:

::

  ssh xenbits.xen.org

  cd ~xen/git/xen.git
  git branch staging-$v staging
  git branch stable-$v master

  cd ~xen/HG/patchbot
  cp xen--master.patchbot-reported-heads xen--stable-$v.patchbot-reported-heads
  cp xen--staging.patchbot-reported-heads xen--staging-$v.patchbot-reported-heads
  $EDITOR versions
  git commit -am "Branch for $v"

  cd ~xendocs/cronjobs
  $EDITOR xenbits-docs-all.sh
  git commit -am "Branch for $v"


On the new branch:

 * Switch to release builds by default.  Commit.

On staging:

 * Update ``XEN_SUBVERSION`` to the next version.  Update
   ``XEN_EXTRAVERSION``, ``README`` and ``SUPPORT.md`` back to ``-unstable``.
   Commit.  Tag the start of the new development window.

 * Rerun ``./autogen.sh`` to refresh the configure scripts.  Commit.

 * Switch ``QEMU_UPSTREAM_REVISION`` back to ``master``.  Commit.

 * Create a new section in ``CHANGELOG.md``.  Commit.

e.g. from Xen 4.21, ``d510f9c1430c^..62d0a92057ca`` and ``d510f9c1430c^..b0255656d121``::

  * 62d0a92057ca - CHANGELOG.md: Start a new 4.22 section
  * 7b88e463f999 - Config.mk: Switch QEMU back to master
  * d954e8c5c8de - Rerun ./autogen.sh for 4.22
  * 85768c28b705 - (tag: 4.22-dev) Update Xen to 4.22
  | * b0255656d121 - (staging-4.21) Switch to release builds by default
  |/
  * d510f9c1430c - doc/man: Align list of viridian default enlightenments with libxl


Releasing
=========

 * Finalise the release dates in ``CHANGELOG.md`` (backported from staging)
   and ``SUPPORT.md`` (only in the release branch).

 * Tag the release in relevant external repos, and update ``Config.mk`` to
   refer to the tag.

 * Update ``XEN_EXTRAVERSION`` to drop the ``-rc`` suffix, and update
   ``README`` to match.  Commit.

 * Tag.  Produce tarballs.

e.g. from Xen 4.20, ``5cd830509d38^..3ad5d648cda5``::

  * 3ad5d648cda5 - (tag: RELEASE-4.20.0) Update to Xen 4.20
  * 89fd1ba88403 - Config.mk: Bump tags to final
  * 6bf05e086765 - SUPPORT.md: Define support lifetime
  * 5cd830509d38 - CHANGELOG.md: Set release date for 4.20


Tagging
=======

 * Confirm that HEAD is on the commit which adjusts ``XEN_EXTRAVERSION``
   suitably.  i.e. ``git show`` shows the intended commit.  Check that all CIs
   are happy with this commit.

 * Tags are expected to be in one of following forms:

   * ``RELEASE-$X.$Y.$Z`` for releases.
   * ``$X.$Y.0-rc$N`` for release candidates.
   * ``$X.$Y-dev`` for development windows.

 * Tags need to be annotated and signed with the appropriate key.  e.g.:

::

  git tag -u 'xen tree' -s -m "Xen $VER.0-rc1" $VER.0-rc1


Producing tarballs
==================

 * Confirm that HEAD is tagged.  i.e. ``git describe`` does not contain a SHA
   on the end.

 * In the root of Xen, run ``make src-tarball-release``.  This produces one or
   more tarballs with different compression schemes.

 * In the CVS repostiory, create a new directory and add it.  Copy the
   tarballs in, sign them and add them.  Commit the result (pushes to the
   server).

 * On mail.xenproject.org, update the webroot.  e.g.:

::

   cd /path/to/xen.git
   make src-tarball-release
   ... # output in dist/

   cd /path/to/xen.org.cvs

   # Make and add new directory
   mkdir oss-xen/release/$VER
   cvs add -kb oss-xen/release/$VER

   # Copy the tarballs, sign and add them
   cp /path/to/xen.git/dist/xen-*.tar.* .
   for t in xen-*.tar.*
   do
       gpg --digest-algo=SHA256 --detach-sign -u 'xen tree' $t
       cvs add -kb $t
       cvs add -kb $t.sig
   done

   # Commit the result (also pushes to the server)
   cvs commit -m $VER

   # SSH to the server and update the webroot
   ssh downloads-cvs@mail.xenproject.org -- \
       'cd /data/downloads.xenproject.org/xen.org/; cvs -q update -d'
