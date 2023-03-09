#
# namcap rules - makepkgfunctions
# Copyright (C) 2017 Kyle Keen <keenerd@gmail.com>
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

import re
from Namcap.ruleclass import PkgbuildRule


class package(PkgbuildRule):
    name = "makepkgfunctions"
    description = "Looks for calls to makepkg functionality"

    def analyze(self, pkginfo, tar):
        bad_calls = ["msg", "msg2", "warning", "error", "plain"]
        regex = re.compile(r"^\s+(%s) " % "|".join(bad_calls))
        hits = set()
        for i in pkginfo.pkgbuild:
            if regex.match(i):
                call = regex.match(i).group(1)
                hits.add(call)
        for i in hits:
            self.warnings.append(("makepkg-function-used %s", i))


# vim: set ts=4 sw=4 noet:
