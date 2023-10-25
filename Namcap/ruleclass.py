# Copyright (C) 2003-2023 Namcap contributors, see AUTHORS for details.
# SPDX-License-Identifier: GPL-2.0-or-later

"""
This module defines the base classes from which Namcap rules are derived
and how they are meant to be used.
"""


# python 3 does not need classes to derive from object
class AbstractRule(object):
    "The parent class of all rules"

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.infos = []


class PkgInfoRule(AbstractRule):
    "The parent class of rules that process package metadata"

    pass


class PkgbuildRule(AbstractRule):
    "The parent class of rules that process PKGBUILDs"

    pass


class TarballRule(AbstractRule):
    "The parent class of rules that process tarballs"

    pass
