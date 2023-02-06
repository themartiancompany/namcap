# 
# namcap rules - licensepkg
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

# List of licenses that are ubiquitous enough to quality as standard instead of
# custom but still need to have their license files packaged to properly
# identify their respective copyright or reserved name clauses. See also
# https://wiki.archlinux.org/title/PKGBUILD#license
special_licenses = [
	"bsd",
	"isc",
	"libpng",
	"ofl",
	"mit",
	"python",
	"zlib"
]

import os.path
from Namcap.ruleclass import *
from Namcap.util import is_debug


def pkg_has_licenses(pkginfo):
	return "license" in pkginfo and len(pkginfo["license"]) > 0


def list_pkg_license_contents(tar):
	return [x for x in tar.getnames() if x.startswith('usr/share/licenses') and not x.endswith('/')]


def has_license_files(licensepaths):
	licensefiles = [os.path.split(x)[1] for x in licensepaths]
	return len(licensefiles) > 0


def list_license_directories(licensepaths):
	return [os.path.split(os.path.split(x)[0])[1] for x in licensepaths]


def list_common_licenses():
	return [x.lower() for x in os.listdir('/usr/share/licenses/common')]


class package(TarballRule):
	name = "licensepkg"
	description = "Verifies license is included in a package file"

	def analyze(self, pkginfo, tar):
		if is_debug(pkginfo):
			return

		if not pkg_has_licenses(pkginfo):
			self.errors.append(("missing-license", ()))
			return

		licensepaths = list_pkg_license_contents(tar)
		licensedirs = list_license_directories(licensepaths)
		commonlicenses = list_common_licenses()

		# Check all licenses for validity
		for license in pkginfo["license"]:
			lowerlicense, _, sublicense = license.lower().partition(':')
			if lowerlicense.startswith('custom') or lowerlicense in special_licenses:
				if pkginfo["name"] not in licensedirs:
					self.errors.append(("missing-custom-license-dir usr/share/licenses/%s", pkginfo["name"]))
				elif not has_license_files(licensepaths):
					self.errors.append(("missing-custom-license-file usr/share/licenses/%s/*", pkginfo["name"]))
			# A common license
			else:
				if lowerlicense not in commonlicenses:
					self.errors.append(("not-a-common-license %s", license))

# vim: set ts=4 sw=4 noet:
