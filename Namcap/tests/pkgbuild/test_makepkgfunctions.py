# namcap tests - makepkgfunctions
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
import Namcap.rules.makepkgfunctions as module


class NamcapMakepkgfunctionsTest(PkgbuildTest):
    pkgbuild1 = """
# Maintainer: Arch Linux <archlinux at example.com>
# Contributor: Arch Linux <archlinux at example.com>

pkgname=mypackage
pkgver=1.0
pkgrel=1
pkgdesc="A package"
arch=('i686' 'x86_64')
url="http://www.example.com/"
license=('GPL')
depends=('glibc')
options=('!libtool')
source=(ftp://ftp.example.com/pub/mypackage-0.1.tar.gz)
md5sums=('abcdefabcdef12345678901234567890')

build() {
  msg "some text"
  msg2 "some text"
  warning "some text"
  error "some text"
  plain "some text"
}

package() {
  true
}
"""
    test_valid = PkgbuildTest.valid_tests

    def preSetUp(self):
        self.rule = module.package

    def test_example1(self):
        bad_calls = ["msg", "msg2", "warning", "error", "plain"]
        r = self.run_on_pkg(self.pkgbuild1)
        self.assertEqual(r.errors, [])
        self.assertEqual(set(r.warnings), set(("makepkg-function-used %s", i) for i in bad_calls))
        self.assertEqual(r.infos, [])


# vim: set ts=4 sw=4 noet:
