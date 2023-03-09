#
# namcap rules - systemdlocation
# Copyright (C) 2015 James Harvey <jamespharvey20@gmail.com>
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

import os
from Namcap.ruleclass import TarballRule


class systemdlocationRule(TarballRule):
    name = "systemdlocation"
    description = "Checks for systemd files in /etc/systemd/system/"

    def analyze(self, pkginfo, tar):
        # don't have this warning for the systemd package
        if "name" in pkginfo:
            if pkginfo["name"] == "systemd":
                return
        # don't have this warning for packages that provides systemd
        if "provides" in pkginfo:
            if "systemd" in pkginfo["provides"]:
                return
        for entry in tar:
            # ignore the actual directory, as that's handled by emptydirs
            if entry.isdir():
                continue

            name = os.path.normpath(entry.name)

            # check for files in /etc/systemd/system/
            if name.startswith("etc/systemd/system/"):
                self.warnings.append(("systemd-location %s", name))


# vim: set ts=4 sw=4 noet:
