#
# namcap rules - rpath
# Copyright (C) 2009 Abhishek Dasgupta <abhidg@gmail.com>
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

from Namcap.util import is_elf
from Namcap.ruleclass import *

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

allowed = ["/usr/lib", "/usr/lib32", "/lib", "$ORIGIN", "${ORIGIN}"]
allowed_toplevels = [s + "/" for s in allowed]
warn = ["/usr/local/lib"]


def get_rpaths(fileobj):
    elffile = ELFFile(fileobj)
    for section in elffile.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            if tag.entry.d_tag != "DT_RPATH":
                continue
            rpaths = tag.rpath
            rpaths = rpaths.split(":")
            for path in rpaths:
                yield path


class package(TarballRule):
    name = "rpath"
    description = "Verifies correct and secure RPATH for files."

    def analyze(self, pkginfo, tar):
        for entry in tar:
            if not entry.isfile():
                continue

            # is it an ELF file ?
            fileobj = tar.extractfile(entry)
            if not is_elf(fileobj):
                continue

            for path in get_rpaths(fileobj):
                path_ok = path in allowed
                for allowed_toplevel in allowed_toplevels:
                    if path.startswith(allowed_toplevel):
                        path_ok = True

                if not path_ok:
                    self.errors.append(("insecure-rpath %s %s", (path, entry.name)))
                    break
                if path in warn and entry.name not in insecure_rpaths:
                    self.warnings.append(("insecure-rpath %s %s", (path, entry.name)))


# vim: set ts=4 sw=4 noet:
