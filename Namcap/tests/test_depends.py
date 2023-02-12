# -*- coding: utf-8 -*-
#
# namcap tests - tests for the depends module
# Copyright (C) 2011 Rémy Oudompheng <remy@archlinux.org>
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

import unittest
import Namcap.depends
import Namcap.package

class DependsTests(unittest.TestCase):
	def setUp(self):
		self.pkginfo = Namcap.package.PacmanPackage({'name': 'package'})

	def test_missing(self):
		self.pkginfo.detected_deps = {"pkg1": []}
		e, w, i = Namcap.depends.analyze_depends(self.pkginfo)
		expected_e = [("dependency-detected-not-included %s (%s)", ("pkg1",''))]
		self.assertEqual(e, expected_e)
		self.assertEqual(w, [])
		self.assertEqual(i,
				[('depends-by-namcap-sight depends=(%s)', 'pkg1')])

	def test_unneeded(self):
		self.pkginfo["depends"] = {"pkg1": []}
		e, w, i = Namcap.depends.analyze_depends(self.pkginfo)
		expected_w = [("dependency-not-needed %s", "pkg1")]
		self.assertEqual(e, [])
		self.assertEqual(w, expected_w)
		self.assertEqual(i,
				[('depends-by-namcap-sight depends=(%s)', '')])

	def test_satisfied(self):
		# false negative test
		self.pkginfo["depends"] = {"readline": []}
		self.pkginfo.detected_deps = {"glibc": [], "readline": []}
		e, w, i = Namcap.depends.analyze_depends(self.pkginfo)
		expected_w = [('dependency-implicitly-satisfied %s (%s)', ('glibc', ''))]
		self.assertEqual(e, [])
		self.assertEqual(w, expected_w)
		# info is verbose and beyond scope, skip it

	def test_satisfied2(self):
		# false positive test
		self.pkginfo["depends"] = {"pyalpm": [], "python": []}
		self.pkginfo.detected_deps = {"pyalpm": [], "python": []}
		e, w, i = Namcap.depends.analyze_depends(self.pkginfo)
		self.assertEqual(e, [])
		self.assertEqual(w, [])
		# info is verbose and beyond scope, skip it

# vim: set ts=4 sw=4 noet:
