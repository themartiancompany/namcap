# namcap rules - perllocal
# Copyright (C) 2003-2009 Jason Chu <jason@archlinux.org>
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

from Namcap.ruleclass import TarballRule


class package(TarballRule):
    name = "perllocal"
    description = "Verifies the absence of perllocal.pod."

    def analyze(self, pkginfo, tar):
        for i in tar.getnames():
            if i.endswith("perllocal.pod"):
                self.errors.append(("perllocal-pod-present %s", i))
