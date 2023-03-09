# namcap tests - shebangdepends
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
#   USA
#

import os
from Namcap.tests.makepkg import MakepkgTest
import Namcap.rules.shebangdepends


class ShebangDependsTest(MakepkgTest):
    pkgbuild = """
pkgname=__namcap_test_shebangdepends
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('any')
url="http://www.example.com/"
license=('GPL')
depends=()
source=()
options=(!purge !zipman)
build() {
  cd "${srcdir}"
  echo -e "#! /usr/bin/env python\nprint('a script')" > python_sample
  echo -e "#!/bin\\xffary/da\\x00ta\ncrash?" > binary_sample
}
package() {
  install -Dm755 "$srcdir/python_sample" "$pkgdir/usr/bin/python_sample"
  install -Dm755 "$srcdir/binary_sample" "$pkgdir/usr/share/binary_sample"
}
"""

    def test_shebangdepends(self):
        "Package with missing python dependency"
        pkgfile = "__namcap_test_shebangdepends-1.0-1-any.pkg.tar"
        with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
            f.write(self.pkgbuild)
        self.run_makepkg()
        pkg, r = self.run_rule_on_tarball(
            os.path.join(self.tmpdir, pkgfile), Namcap.rules.shebangdepends.ShebangDependsRule
        )
        e, w, i = Namcap.depends.analyze_depends(pkg)
        self.assertEqual(
            e,
            [
                (
                    "dependency-detected-not-included %s (%s)",
                    ("python", "programs ['python'] needed in scripts ['usr/bin/python_sample']"),
                )
            ],
        )
        self.assertEqual(w, [])


# vim: set ts=4 sw=4 noet:
