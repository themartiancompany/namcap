# namcap tests - glibfiles
# Copyright (C) 2011 Rémy Oudompheng <remy@archlinux.org>
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
import Namcap.rules.pathdepends


class PathDependsTest(MakepkgTest):
    pkgbuild = """
pkgname=__namcap_test_pathdepends
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('i686' 'x86_64')
url="http://www.example.com/"
license=('GPL')
depends=('glibc')
source=()
options=(!purge !zipman)
build() {
  true
}
package() {
  # dconf-needed-for-glib-schemas
  mkdir -p "${pkgdir}/usr/share/glib-2.0/schemas"
  touch "${pkgdir}/usr/share/glib-2.0/schemas/org.test.gschema.xml"

  # glib2-needed-for-gio-modules
  mkdir -p "${pkgdir}/usr/lib/gio/modules"
  touch "${pkgdir}/usr/lib/gio/modules/something.so"

  # hicolor-icon-theme-needed-for-hicolor-dir
  mkdir -p "${pkgdir}/usr/share/icons/hicolor/64x64/apps"
  touch "${pkgdir}/usr/share/icons/hicolor/64x64/apps/example.png"
}
"""

    def test_pathdepends_exists(self):
        pkgfile = "__namcap_test_pathdepends-1.0-1-%(arch)s.pkg.tar" % {"arch": self.arch}
        with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
            f.write(self.pkgbuild)
        self.run_makepkg()
        pkg, r = self.run_rule_on_tarball(os.path.join(self.tmpdir, pkgfile), Namcap.rules.pathdepends.PathDependsRule)
        self.assertEqual(
            pkg.detected_deps,
            {
                "dconf": [("dconf-needed-for-glib-schemas", ())],
                "glib2": [("glib2-needed-for-gio-modules", ())],
                "hicolor-icon-theme": [("hicolor-icon-theme-needed-for-hicolor-dir", ())],
            },
        )
        self.assertEqual(r.errors, [])
        self.assertEqual(r.warnings, [])
        self.assertEqual(r.infos, [])
