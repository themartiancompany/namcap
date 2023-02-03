# -*- coding: utf-8 -*-
#
# namcap rules - sodepends
# Copyright (C) 2003-2009 Jason Chu <jason@archlinux.org>
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 

"""Checks dependencies resulting from linking of shared libraries."""

from collections import defaultdict
import re
import os
import subprocess
import Namcap.package
from Namcap.ruleclass import *
from Namcap.util import is_elf
from Namcap.rules.rpath import get_rpaths

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

libcache = {'i686': {}, 'x86-64': {}}

def scanlibs(fileobj, filename, custom_libs, liblist, libdepends, libprovides):
	"""
	Find shared libraries in a file-like binary object

	If it depends on a library or provides one, store that library's path.
	"""

	if not is_elf(fileobj):
		return {}

	elffile = ELFFile(fileobj)
	for section in elffile.iter_sections():
		if not isinstance(section, DynamicSection):
			continue
		for tag in section.iter_tags():
			# DT_SONAME means it provides a library; ignore unversioned (mostly internal) libraries
			if tag.entry.d_tag == 'DT_SONAME' and not tag.soname.endswith('.so'):
				soname = tag.soname.rsplit('.so', 1)[0] + '.so'
				libprovides[soname].add(filename)
			# DT_NEEDED means shared library
			if tag.entry.d_tag != 'DT_NEEDED':
				continue
			bitsize = elffile.elfclass
			architecture = {32:'i686', 64:'x86-64'}[bitsize]
			libname = tag.needed
			soname = libname.rsplit('.so', 1)[0] + '.so'
			libdepends[soname].add(filename)
			if libname in custom_libs:
				liblist[custom_libs[libname][1:]].add(filename)
				continue
			try:
				libpath = os.path.abspath(
						libcache[architecture][libname])[1:]
				liblist[libpath].add(filename)
			except KeyError:
				# We didn't know about the library, so add it for fail later
				liblist[libname].add(filename)

def finddepends(liblist):
	"""
	Find packages owning a list of libraries

	Returns:
	  dependlist -- a dictionary { package => set(libraries) }
	  libdependlist -- a dictionary { soname => package }
	  orphans -- the list of libraries without owners
	  missing_provides -- the list of sonames without providers
	"""
	dependlist = defaultdict(set)
	libdependlist = {}
	missing_provides = {}

	somatches = {}
	actualpath = {}

	knownlibs = set(liblist)
	foundlibs = set()

	actualpath = dict((j, os.path.realpath('/' + j)[1:]) for j in knownlibs)

	# Sometimes packages don't include all so .so, .so.1, .so.1.13, .so.1.13.19 files
	# They rely on ldconfig to create all the symlinks
	# So we will strip off the matching part of the files and use this regexp to match the rest
	so_end = re.compile('(\.\d+)*')
	# Whether we should even look at a particular file
	is_so = re.compile('\.so')

	for pkg in Namcap.package.get_installed_packages():
		for j, fsize, fmode in pkg.files:
			if not is_so.search(j):
				continue

			for k in knownlibs:
				# File must be an exact match or have the right .so ending numbers
				# i.e. gpm includes libgpm.so and libgpm.so.1.19.0, but everything links to libgpm.so.1
				# We compare find libgpm.so.1.19.0 startswith libgpm.so.1 and .19.0 matches the regexp
				if j == actualpath[k] or (j.startswith(actualpath[k]) and so_end.match(j[len(actualpath[k]):])):
					dependlist[pkg.name].add(k)
					foundlibs.add(k)
					# Check if the dependency can be satisfied by soname
					soname = os.path.basename(k).rsplit('.so', 1)[0] + '.so'
					stripped_provides = [Namcap.package.strip_depend_info(d) for d in pkg.provides]
					if soname in stripped_provides:
						libdependlist[soname] = pkg.name
					else:
						missing_provides[soname] = pkg.name

	orphans = list(knownlibs - foundlibs)
	return dependlist, libdependlist, orphans, missing_provides

def filllibcache():
	var = subprocess.Popen('ldconfig -p', 
			env = {"LANG": "C"},
			shell=True,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE).communicate()
	libline = re.compile('\s*(.*) \((.*)\) => (.*)')
	for j in var[0].decode('ascii').splitlines():
		g = libline.match(j)
		if g != None:
			if g.group(2).startswith('libc6,x86-64'):
				libcache['x86-64'][g.group(1)] = g.group(3)
			else:
				# TODO: This is bogus; what do non x86-architectures print?
				libcache['i686'][g.group(1)] = g.group(3)


class SharedLibsRule(TarballRule):
	name = "sodepends"
	description = "Checks dependencies caused by linked shared libraries"
	def analyze(self, pkginfo, tar):
		liblist = defaultdict(set)
		libdepends = defaultdict(set)
		libprovides = defaultdict(set)
		dependlist = {}
		libdependlist = {}
		missing_provides = {}
		filllibcache()
		os.environ['LC_ALL'] = 'C'
		pkg_so_files = ['/' + n for n in tar.getnames() if '.so' in n]

		for entry in tar:
			if not entry.isfile():
				continue
			f = tar.extractfile(entry)
			# find anything that could be rpath related
			rpath_files = {}
			if is_elf(f):
				rpaths = list(get_rpaths(f))
				f.seek(0)
				for n in pkg_so_files:
					if any(n.startswith(rp) for rp in rpaths):
						rpath_files[os.path.basename(n)] = n
			scanlibs(f, entry.name, rpath_files, liblist, libdepends, libprovides)
			f.close()

		# Ldd all the files and find all the link and script dependencies
		dependlist, libdependlist, orphans, missing_provides = finddepends(liblist)

		# Handle "no package associated" errors
		self.warnings.extend([("library-no-package-associated %s", i)
			for i in orphans])

		# Hanle when a required soname does not provided by the associated package yet
		self.infos.extend([("libdepends-missing-provides %s %s", (i, missing_provides[i]))
			for i in missing_provides])

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

		# Check for soname dependencies, filter out internal dependencies
		libdependlist = dict(filter(lambda elem: elem[1] != pkginfo["name"], libdependlist.items()))

		for i in libdependlist:
			if i in pkginfo["depends"]:
				self.infos.append(("libdepends-detected-satisfied %s %s (%s)", (i, libdependlist[i], str(list(libdepends[i])))))
				continue
			if i in pkginfo["optdepends"]:
				self.warnings.append(("libdepends-detected-but-optional %s %s (%s)", (i, libdependlist[i], str(list(libdepends[i])))))
				continue
			self.warnings.append(("libdepends-detected-not-included %s %s (%s)", (i, libdependlist[i], str(list(libdepends[i])))))

		for i in pkginfo["depends"]:
			if i.endswith('.so') and i not in libdependlist:
				self.warnings.append(("libdepends-not-needed %s", i))

		self.infos.append(("libdepends-by-namcap-sight depends=(%s)", ' '.join(libdependlist) ))

		# Check provided libraries
		for i in libprovides:
			if i in pkginfo["provides"]:
				self.infos.append(("libprovides-satisfied %s %s", (i, str(list(libprovides[i])))))
				continue
			self.warnings.append(("libprovides-unsatisfied %s %s", (i, str(list(libprovides[i])))))

		for i in pkginfo["provides"]:
			if i.endswith('.so') and i not in libprovides:
				self.errors.append(("libprovides-missing %s", i))

		self.infos.append(("libprovides-by-namcap-sight provides=(%s)", ' '.join(libprovides) ))

		# Check for packages in testing
		for i in dependlist.keys():
			p = Namcap.package.load_testing_package(i)
			q = Namcap.package.load_from_db(i)
			if p is not None and q is not None and p["version"] == q["version"] :
				self.warnings.append(("dependency-is-testing-release %s", i))

# vim: set ts=4 sw=4 noet:
