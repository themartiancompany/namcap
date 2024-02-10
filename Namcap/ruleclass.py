# Copyright (C) 2003-2023 Namcap contributors, see AUTHORS for details.
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Any

"""
This module defines the base classes from which Namcap rules are derived
and how they are meant to be used.
"""


# python 3 does not need classes to derive from object
class AbstractRule(object):
    "The parent class of all rules"

    enable: bool = True

    def __init__(self):
        self.errors: list[tuple[str, tuple[Any, ...]]] = []
        self.warnings: list[tuple[str, tuple[Any, ...]]] = []
        self.infos: list[tuple[str, tuple[Any, ...]]] = []


class PkgInfoRule(AbstractRule):
    "The parent class of rules that process package metadata"


class PkgbuildRule(AbstractRule):
    "The parent class of rules that process PKGBUILDs"


class TarballRule(AbstractRule):
    "The parent class of rules that process tarballs"
