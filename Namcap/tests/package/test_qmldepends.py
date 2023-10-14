# Copyright (C) 2003-2023 Namcap contributors, see AUTHORS for details.
# SPDX-License-Identifier: GPL-2.0-or-later

import os
from Namcap.tests.makepkg import MakepkgTest
import Namcap.rules.qmldepends


class QmlDependsTest(MakepkgTest):
    pkgbuild = """
pkgname=__namcap_test_qmldepends
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('any')
url="http://www.example.com/"
license=('GPL')
depends=()
source=()
build() {
  echo "import QtQuick.Window 2.0" > main.qml
  echo "import QtTest" > not-a-qml-file
}
package() {
  install -Dm 644 main.qml not-a-qml-file -t "$pkgdir"/usr/bin
}
"""

    def test_qmldepends(self):
        "Package with missing pacman dependency"
        pkgfile = "__namcap_test_qmldepends-1.0-1-any.pkg.tar"
        with open(os.path.join(self.tmpdir, "PKGBUILD"), "w") as f:
            f.write(self.pkgbuild)
        self.run_makepkg()
        pkg, r = self.run_rule_on_tarball(
            os.path.join(self.tmpdir, pkgfile), Namcap.rules.qmldepends.QmlDependencyRule
        )
        self.assertEqual(
            r.warnings,
            [
                (
                    'qml-module-no-package-associated %s %s',
                    ('QtQuick.Window', "['usr/bin/main.qml']")
                )
            ],
        )
        self.assertEqual(r.errors, [])
