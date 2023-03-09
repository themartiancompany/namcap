# namcap rules - pathdepends
# Copyright (C) 2016 Kyle Keen <keenerd@gmail.com>
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
#

"""
This contains a collection of essentially one-line rules:
If a certain path is detected then a certain dependency is expected.

Anything fancier than this should get its own rule.
"""

import re
from Namcap.ruleclass import TarballRule


class PathDependsRule(TarballRule):
    name = "pathdepends"
    description = "Check for simple implicit path dependencies"
    # list of path regex, dep name, reason tag
    subrules = [
        {"path": "^usr/share/glib-2\.0/schemas$", "dep": "dconf", "reason": "dconf-needed-for-glib-schemas"},
        {"path": "^usr/lib/gio/modules/.*\.so$", "dep": "glib2", "reason": "glib2-needed-for-gio-modules"},
        {
            "path": "^usr/share/icons/hicolor$",
            "dep": "hicolor-icon-theme",
            "reason": "hicolor-icon-theme-needed-for-hicolor-dir",
        },
    ]

    def analyze(self, pkginfo, tar):
        names = [entry.name for entry in tar]
        for subrule in self.subrules:
            pattern = re.compile(subrule["path"])
            if any(pattern.search(n) for n in names):
                dep = subrule["dep"]
                reason = subrule["reason"]
                pkginfo.detected_deps[dep].append((reason, ()))


# vim: set ts=4 sw=4 noet:
