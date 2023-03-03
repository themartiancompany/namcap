#
# namcap rules - hookdepends
# Copyright (C) 2019 Eli Schwartz <eschwartz at archlinux.org>
# Copyright (C) 2016 Kyle Keen <keenerd at gmail.com>
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

import re
from Namcap.ruleclass import *

class HookDependsRule(TarballRule):
	name = "hookdepends"
	description = "Check for redundant hook dependencies"
	subrules = [
		{
			'path': '^usr/share/applications/.*\.desktop$',
			'dep': 'desktop-file-utils',
		},
		{
			'path': '^usr/share/mime$',
			'dep': 'shared-mime-info',
		}
	]
	def analyze(self, pkginfo, tar):
		names = [entry.name for entry in tar]
		for subrule in self.subrules:
			dep = subrule['dep']
			if dep not in pkginfo['depends']:
				continue
			pattern = re.compile(subrule['path'])
			if any(pattern.search(n) for n in names):
				self.warnings.append(('external-hooks-unneeded %s', dep))


# vim: set ts=4 sw=4 noet:
