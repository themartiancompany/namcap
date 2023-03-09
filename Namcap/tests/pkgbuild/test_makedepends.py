# namcap tests - makedepends
# Copyright (C) 2011 R?my Oudompheng <remy at archlinux.org>
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

from Namcap.tests.pkgbuild_test import PkgbuildTest
import Namcap.rules.makedepends as module


class NamcapRedundantMakedependsTest(PkgbuildTest):
    pkgbuild1 = """
# Maintainer: Arch Linux <archlinux at example.com>
# Contributor: Arch Linux <archlinux at example.com>

pkgname=mypackage
pkgver=1.0
pkgrel=1
pkgdesc="A package"
url="http://www.example.com/"
arch=('i686' 'x86_64')
depends=('lib1' 'lib2' 'lib3')
makedepends=('lib1' 'lib2' 'lib4')
license=('GPL')
options=('!libtool')
source=(ftp://ftp.example.com/pub/mypackage-0.1.tar.gz)
md5sums=('abcdefabcdef12345678901234567890')

build() {
  true
}

package() {
  true
}
"""
    test_valid = PkgbuildTest.valid_tests

    def preSetUp(self):
        self.rule = module.RedundantMakedepends

    def test_example1(self):
        # Example 1
        r = self.run_on_pkg(self.pkgbuild1)
        self.assertEqual(r.errors, [])
        self.assertEqual(set(r.warnings), set(("redundant-makedep %s", i) for i in ["lib1", "lib2"]))
        self.assertEqual(r.infos, [])


class NamcapVCSMakedependsTest(PkgbuildTest):
    pkgbuild1 = """
# Maintainer: Arch Linux <archlinux at example.com>
# Contributor: Arch Linux <archlinux at example.com>

pkgname=mypackage
pkgver=1.0
pkgrel=1
pkgdesc="A package"
url="http://www.example.com/"
arch=('i686' 'x86_64')
depends=()
makedepends=()
license=('GPL')
options=('!libtool')
source=(name::bzr+https://example.com/pub/mypackage
        name::git://example.com/pub/mypackage
        hg+https://example.com/pub/mypackage
        svn://example.com/pub/mypackage)
md5sums=('abcdefabcdef12345678901234567890')

build() {
  true
}

package() {
  true
}
"""
    test_valid = PkgbuildTest.valid_tests

    def preSetUp(self):
        self.rule = module.VCSMakedepends

    def test_example1(self):
        # Example 1
        makedeps = ["breezy", "git", "mercurial", "subversion"]
        r = self.run_on_pkg(self.pkgbuild1)
        self.assertEqual(r.errors, [])
        self.assertEqual(set(r.warnings), set(("missing-vcs-makedeps %s", i) for i in makedeps))
        self.assertEqual(r.infos, [])

    def test_example2(self):
        # Example 2
        r = self.run_on_pkg(self.pkgbuild1 + "source=(gitsomething)")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.warnings, [])
        self.assertEqual(r.infos, [])


# vim: set ts=4 sw=4 noet:
