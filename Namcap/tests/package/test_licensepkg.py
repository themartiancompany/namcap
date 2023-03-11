# Copyright (C) 2003-2023 Namcap contributors, see AUTHORS for details.
# SPDX-License-Identifier: GPL-2.0-or-later

import os
from Namcap.tests.makepkg import MakepkgTest
import Namcap.rules.licensepkg


class LicenseFileTest(MakepkgTest):
    pkgbuild = """
pkgname=__namcap_test_licensepkg
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('i686' 'x86_64')
url="http://www.example.com/"
license=('custom:DWTFYWL')
depends=('glibc')
source=()
options=(!purge !zipman)
build() {
  true
}
package() {
  mkdir -p "${pkgdir}/usr/share"
  touch "${pkgdir}/usr/share/somefile"
}
"""

    def test_licensepkg_file_exists(self):
        pkgfile = "__namcap_test_licensepkg-1.0-1-%(arch)s.pkg.tar" % {"arch": self.arch}
        with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
            f.write(self.pkgbuild)
        self.run_makepkg()
        pkg, r = self.run_rule_on_tarball(os.path.join(self.tmpdir, pkgfile), Namcap.rules.licensepkg.package)
        expect = ("missing-custom-license-dir usr/share/licenses/%s", "__namcap_test_licensepkg")
        self.assertEqual(r.errors, [expect])
        self.assertEqual(r.warnings, [])
        self.assertEqual(r.infos, [])

    pkgbuild_creativecommons = """
pkgname=__namcap_test_licensepkg
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('i686' 'x86_64')
url="http://www.example.com/"
license=('CCPL:cc-by-sa-3.0')
depends=('glibc')
source=()
options=(!purge !zipman)
build() {
  true
}
package() {
  mkdir -p "${pkgdir}/usr/share"
  touch "${pkgdir}/usr/share/somefile"
}
"""

    def test_licensepkg_cc(self):
        pkgfile = "__namcap_test_licensepkg-1.0-1-%(arch)s.pkg.tar" % {"arch": self.arch}
        with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
            f.write(self.pkgbuild_creativecommons)
        self.run_makepkg()
        pkg, r = self.run_rule_on_tarball(os.path.join(self.tmpdir, pkgfile), Namcap.rules.licensepkg.package)
        self.assertEqual(r.errors, [])
        self.assertEqual(r.warnings, [])
        self.assertEqual(r.infos, [])

    pkgbuild_wronglicense = """
pkgname=__namcap_test_licensepkg
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('i686' 'x86_64')
url="http://www.example.com/"
license=('DWTFYWL')
depends=('glibc')
source=()
options=(!purge !zipman)
build() {
  true
}
package() {
  mkdir -p "${pkgdir}/usr/share"
  touch "${pkgdir}/usr/share/somefile"
}
"""

    def test_licensepkg_wrong(self):
        pkgfile = "__namcap_test_licensepkg-1.0-1-%(arch)s.pkg.tar" % {"arch": self.arch}
        with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
            f.write(self.pkgbuild_wronglicense)
        self.run_makepkg()
        pkg, r = self.run_rule_on_tarball(os.path.join(self.tmpdir, pkgfile), Namcap.rules.licensepkg.package)
        self.assertEqual(r.errors, [("not-a-common-license %s", "DWTFYWL")])
        self.assertEqual(r.warnings, [])
        self.assertEqual(r.infos, [])
