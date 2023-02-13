# -*- coding: utf-8 -*-
#
# namcap tests - pydepends
# Copyright (C) 2020 Felix Yan <felixonmars at archlinux.org>
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
#   USA
#

import os
from Namcap.tests.makepkg import MakepkgTest
import Namcap.rules.pydepends


class PyDependsTest(MakepkgTest):
	pkgbuild = """
pkgname=__namcap_test_pydepends
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('any')
url="http://www.example.com/"
license=('GPL')
depends=('python-six')
source=()
build() {
  cd "${srcdir}"
  echo "import six, pyalpm" > main.py
  echo "(^y^)" > invalid.py
}
package() {
  install -D -m 755 "$srcdir/main.py" "$pkgdir/usr/bin/main.py"
}
"""
	def test_pydepends(self):
		"Package with missing pacman dependency"
		pkgfile = "__namcap_test_pydepends-1.0-1-any.pkg.tar"
		with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
			f.write(self.pkgbuild)
		self.run_makepkg()
		pkg, r = self.run_rule_on_tarball(
				os.path.join(self.tmpdir, pkgfile),
				Namcap.rules.pydepends.PythonDependencyRule
				)
		self.assertEqual(pkg.detected_deps['pyalpm'], [
			('python-modules-needed %s %s',
			 (str(["pyalpm"]), str(["usr/bin/main.py"])))
			]
		)
		e, w, i = Namcap.depends.analyze_depends(pkg)
		self.assertEqual(e, [
			('dependency-detected-not-included %s (%s)',
				('pyalpm', "python modules ['pyalpm'] needed in files ['usr/bin/main.py']"))
		])
		self.assertEqual(w, [])

# vim: set ts=4 sw=4 noet:
