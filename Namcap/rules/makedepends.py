#
# namcap rules - makedepends
# Copyright (C) 2018 Michael Straube <michael.straube at posteo.de>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

from Namcap.ruleclass import *


class RedundantMakedepends(PkgbuildRule):
    """
    This rule checks for make dependencies that are already
    included as dependencies.
    """

    name = "redundant_makedepends"
    description = "Check for redundant make dependencies"

    def analyze(self, pkginfo, pkgbuild):
        redundant_makedeps = []

        if "makedepends" not in pkginfo:
            return
        if "depends" not in pkginfo:
            return
        redundant_makedeps.extend(set(pkginfo["makedepends"]) & set(pkginfo["depends"]))

        for i in redundant_makedeps:
            self.warnings.append(("redundant-makedep %s", i))


class VCSMakedepends(PkgbuildRule):
    """
    This rule checks for missing VCS make dependencies.
    """

    name = "vcs_makedepends"
    description = "Verify make dependencies for VCS sources"

    def analyze(self, pkginfo, pkgbuild):
        vcs = {
            "bzr": "breezy",
            "git": "git",
            "hg": "mercurial",
            "svn": "subversion",
        }
        missing = []
        protocols = set()

        if "source" not in pkginfo:
            return

        for s in pkginfo["source"]:
            p = s.split("::", 1)[-1]
            p = p.split("://", 1)[0]
            p = p.split("+", 1)[0]
            if p in vcs:
                protocols.add(p)

        if not protocols:
            return

        for v in protocols:
            d = vcs[v]
            if "makedepends" not in pkginfo:
                missing.append(d)
                continue
            if d not in pkginfo["makedepends"]:
                missing.append(d)

        for i in missing:
            self.warnings.append(("missing-vcs-makedeps %s", i))


# vim: set ts=4 sw=4 noet:
