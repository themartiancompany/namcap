# 
# namcap rules - externalhooks
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
# 

from Namcap.ruleclass import *

class ExternalHooksRule(TarballRule):
	name = "externalhooks"
	description = "Check the .INSTALL for commands covered by hooks"
	hooked = [
		'update-desktop-database',
		'update-mime-database',
		'install-info',
		'glib-compile-schemes',
		'gtk-update-icon-cache',
		'xdg-icon-resource',
		'gconfpkg',
		'gio-querymodules',
		'fc-cache',
		'mkfontscale',
		'mkfontdir',
		'systemd-sysusers',
		'systemd-tmpfiles',
		'vlc-cache-gen',
	]
	def analyze(self, pkginfo, tar):
		if ".INSTALL" not in tar.getnames():
			return
		f = tar.extractfile(".INSTALL")
		text = f.read().decode('utf-8', 'ignore')
		f.close()
		for command in self.hooked:
			if command in text:
				self.warnings.append(('external-hooks %s', command))

# vim: set ts=4 sw=4 noet:
