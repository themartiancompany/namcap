# -*- coding: utf-8 -*-
#
# namcap rules - pydepends
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

from collections import defaultdict
import ast
import sys
import sysconfig
import Namcap.package
from Namcap.ruleclass import *


def finddepends(liblist):
	"""
	Find packages owning a list of libraries

	Returns:
	  dependlist -- a dictionary { package => set(libraries) }
	  orphans -- the list of libraries without owners
	"""
	dependlist = defaultdict(set)

	knownlibs = set(liblist)
	foundlibs = set()

	workarounds = {
		"python": sys.builtin_module_names
	}

	for pkg in Namcap.package.get_installed_packages():
		for j, fsize, fmode in pkg.files:
			if not j.startswith("usr/lib/python3"):
				continue

			for k in knownlibs:
				if j.endswith("site-packages/" + k + "/") or j.endswith("site-packages/" + k + ".py") or \
						j.endswith("site-packages/" + k + ".so") or \
						j.endswith("site-packages/" + k + ".abi3.so") or \
						j.endswith("site-packages/" + k + sysconfig.get_config_var('EXT_SUFFIX')) or \
						j.endswith("lib-dynload/" + k + sysconfig.get_config_var('EXT_SUFFIX')) or \
						j.count("/") == 3 and j.endswith("/" + k + ".py") or \
						j.count("/") == 4 and j.endswith("/" + k + "/") or \
						pkg.name in workarounds and k in workarounds[pkg.name]:
					dependlist[pkg.name].add(k)
					foundlibs.add(k)

	orphans = list(knownlibs - foundlibs)
	return dependlist, orphans


def get_imports(file):
	try:
		root = ast.parse(file.read())
	except (SyntaxError, ValueError):
		# ast.parse() uses compile(), which may raise SyntaxError or ValueError
		return

	for node in ast.walk(root):
		if isinstance(node, ast.Import):
			for module in node.names:
				yield module.name.split('.')[0]
		elif isinstance(node, ast.ImportFrom):
			if node.module and node.level == 0:
				yield node.module.split('.')[0]


class PythonDependencyRule(TarballRule):
	name = "pydepends"
	description = "Checks python dependencies"
	def analyze(self, pkginfo, tar):
		liblist = defaultdict(set)
		own_liblist = set()

		for entry in tar:
			if not entry.isfile() or not entry.name.endswith('.py'):
				continue
			own_liblist.add(entry.name[:-3])
			f = tar.extractfile(entry)
			for module in get_imports(f):
				liblist[module].add(entry.name)
			f.close()

		for lib in own_liblist:
			liblist.pop(lib, None)

		dependlist, orphans = finddepends(liblist)

		# Handle "no package associated" errors
		self.warnings.extend([("library-no-package-associated %s %s", (i, str(list(liblist[i]))))
			for i in orphans])

		# Print link-level deps
		for pkg, libraries in dependlist.items():
			if isinstance(libraries, set):
				files = list(libraries)
				needing = set().union(*[liblist[lib] for lib in libraries])
				reasons = pkginfo.detected_deps.setdefault(pkg, [])
				reasons.append((
					"libraries-needed %s %s",
					(str(files), str(list(needing)))
					))
				self.infos.append(("link-level-dependence %s in %s", (pkg, str(files))))

		# Check for packages in testing
		for i in dependlist.keys():
			p = Namcap.package.load_testing_package(i)
			q = Namcap.package.load_from_db(i)
			if p is not None and q is not None and p["version"] == q["version"] :
				self.warnings.append(("dependency-is-testing-release %s", i))
# vim: set ts=4 sw=4 noet:
