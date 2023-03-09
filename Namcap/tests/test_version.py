# namcap tests - tests for the version module
# Copyright (C) 2015 Rikard Falkeborn <rikard.falkeborn@gmail.com>
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

import os
import unittest
import re
import Namcap.version


class VersionTests(unittest.TestCase):
    def test_manpage(self):
        """Test that the manpage and program has the same version."""
        here = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(here, "..", "..", "namcap.1")) as f:
            first_line = f.readline()
        match = re.search('"namcap (.*?)"', first_line)
        self.assertEqual(match.group(1), Namcap.version.get_version())


# vim: set ts=4 sw=4 noet:
