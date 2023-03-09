# namcap rules - package variables
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

"These rules checks basic sanity of package metadata"

import re
import os
from Namcap.ruleclass import PkgInfoRule, PkgbuildRule
from Namcap.util import is_debug


class CapsPkgnameRule(PkgInfoRule):
    name = "capsnamespkg"
    description = "Verifies package name in package does not include upper case letters"

    def analyze(self, pkginfo, tar):
        if re.search("[A-Z]", pkginfo["name"]) is not None:
            self.errors.append(("package-name-in-uppercase", ()))


class UrlRule(PkgInfoRule):
    name = "urlpkg"
    description = "Verifies url is included in a package file"

    def analyze(self, pkginfo, tar):
        if "url" not in pkginfo:
            self.errors.append(("missing-url", ()))


class LicenseRule(PkgInfoRule):
    name = "license"
    description = "Verifies license is included in a PKGBUILD"

    def analyze(self, pkginfo, tar):
        if is_debug(pkginfo):
            return
        if "license" not in pkginfo or len(pkginfo["license"]) == 0:
            self.errors.append(("missing-license", ()))


class NonUniqueSourcesRule(PkgbuildRule):
    name = "non-unique-source"
    description = "Verifies the downloaded sources have a unique filename"

    def analyze(self, pkginfo, tar):
        for source_file in pkginfo["source"]:
            if "::" not in source_file and re.match(
                r"^[vV]?(([0-9]){8}|([0-9]+\.?)+)\.", os.path.basename(source_file)
            ):
                self.warnings.append(("non-unique-source-name %s", os.path.basename(source_file)))


# vim: set ts=4 sw=4 noet:
