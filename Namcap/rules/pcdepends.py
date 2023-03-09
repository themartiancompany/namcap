# -*- coding: utf-8 -*-
#
# namcap rules - pcdepends
# Copyright (C) 2023 Balló György <bgyorgy at archlinux.org>
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

"""Checks dependencies resulting from pkg-config files."""

from collections import defaultdict
import subprocess
import Namcap.package
from Namcap.ruleclass import *

def scanpcfiles(pkg_pc_files, pclist):
	"""
	Find dependencies of pkg-config files
	"""

	for f in pkg_pc_files:
		if f.startswith('usr/lib/pkgconfig') or f.startswith('usr/share/pkgconfig'):
			pcname = f.replace('usr/lib/pkgconfig/', '').replace('usr/share/pkgconfig/', '').replace('.pc', '')
			pkgconfig_command = 'pkg-config'
		elif f.startswith('usr/lib32/pkgconfig'):
			pcname = f.replace('usr/lib32/pkgconfig/', '').replace('.pc', '')
			pkgconfig_command = 'i686-pc-linux-gnu-pkg-config'
		else:
			continue

		var = subprocess.Popen([pkgconfig_command, '--maximum-traverse-depth', '1', '--print-requires', '--print-requires-private',  pcname],
				env = {"LANG": "C"},
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE).communicate()
		for j in var[0].decode('ascii').splitlines():
			# Remove version numbers
			pc_pkg = j.split(' ', 1)[0]
			if pc_pkg is not None:
				var = subprocess.Popen([pkgconfig_command, '--maximum-traverse-depth', '1', '--path',  pc_pkg],
						env = {"LANG": "C"},
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE).communicate()
				pc_path = var[0].decode('ascii').splitlines()
				if pc_path:
					pclist[pc_path[0][1:]].add(f)
				else:
					pclist[pc_pkg + '.pc'].add(f)

def finddepends(pclist):
	"""
	Find packages owning a list of pkg-config files

	Returns:
	  dependlist -- a dictionary { package => set(pclist) }
	  orphans -- the list of pkg-config files without owners
	"""
	dependlist = defaultdict(set)
	knownpcs = set(pclist)
	foundpcs = set()

	for pkg in Namcap.package.get_installed_packages():
		for fname, fsize, fmode in pkg.files:
			for k in knownpcs:
				if fname == k:
					dependlist[pkg.name].add(k)
					foundpcs.add(k)

	orphans = list(knownpcs - foundpcs)
	return dependlist, orphans


class PkgConfigDependenciesRule(TarballRule):
	name = "pcdepends"
	description = "Checks dependencies caused by pkg-config files"
	def analyze(self, pkginfo, tar):
		pclist = defaultdict(set)
		dependlist = {}
		pkg_pc_files = [f for f in tar.getnames() if '.pc' in f]

		# Detect dependencies from pkg-config files
		scanpcfiles(pkg_pc_files, pclist)

		# Find the packages wich contain the pkg-config files
		dependlist, orphans = finddepends(pclist)

		# Handle "no package associated" errors
		self.warnings.extend([("pkgconf-no-package-associated %s %s", (i, str(list(pclist[i]))))
			for i in orphans])

		# Print deps
		for pkg, libraries in dependlist.items():
			if isinstance(libraries, set):
				files = list(libraries)
				needing = set().union(*[pclist[lib] for lib in libraries])
				reasons = pkginfo.detected_deps.setdefault(pkg, [])
				reasons.append((
					"pkgconf-needed %s %s",
					(str(files), str(list(needing)))
					))
				self.infos.append(("pkgconf-dependence %s in %s", (pkg, str(files))))

# vim: set ts=4 sw=4 noet:
