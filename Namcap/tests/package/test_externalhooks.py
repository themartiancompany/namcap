# namcap tests - externalhooks rule
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

import os
from Namcap.tests.makepkg import MakepkgTest
import Namcap.rules.externalhooks


class ExternalHooksTest(MakepkgTest):
    pkgbuild_generic = """
pkgname=__namcap_test_externalhooks
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('any')
url="http://www.example.com/"
license=('GPL')
depends=('glibc')
options=(emptydirs)
install=sample.install
source=()
build() {
  true
}
package() {
  true
}

"""
    install_bad = """
post_install() {
  update-desktop-database -q
  gtk-update-icon-cache -q -t -f usr/share/icons/hicolor
}
"""
    install_good = """
post_install() {
  true
}
"""

    def test_bad_install(self):
        pkgfile = "__namcap_test_externalhooks-1.0-1-any.pkg.tar"
        with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
            f.write(self.pkgbuild_generic)
        with open(os.path.join(self.tmpdir, "sample.install"), "w") as f:
            f.write(self.install_bad)
        self.run_makepkg()
        pkg, r = self.run_rule_on_tarball(
            os.path.join(self.tmpdir, pkgfile), Namcap.rules.externalhooks.ExternalHooksRule
        )
        self.assertEqual(r.errors, [])
        self.assertEqual(
            r.warnings,
            [("external-hooks %s", "update-desktop-database"), ("external-hooks %s", "gtk-update-icon-cache")],
        )
        self.assertEqual(r.infos, [])

    def test_good_install(self):
        pkgfile = "__namcap_test_externalhooks-1.0-1-any.pkg.tar"
        with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
            f.write(self.pkgbuild_generic)
        with open(os.path.join(self.tmpdir, "sample.install"), "w") as f:
            f.write(self.install_good)
        self.run_makepkg()
        pkg, r = self.run_rule_on_tarball(
            os.path.join(self.tmpdir, pkgfile), Namcap.rules.externalhooks.ExternalHooksRule
        )
        self.assertEqual(r.errors, [])
        self.assertEqual(r.warnings, [])
        self.assertEqual(r.infos, [])


# vim: set ts=4 sw=4 noet:
