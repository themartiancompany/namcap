# Copyright (C) 2003-2023 Namcap contributors, see AUTHORS for details.
# SPDX-License-Identifier: GPL-2.0-or-later

import os.path
from Namcap.ruleclass import TarballRule
from Namcap.package import load_from_db
from Namcap.util import is_debug

# List of licenses that are ubiquitous enough to quality as standard instead of
# custom but still need to have their license files packaged to properly
# identify their respective copyright or reserved name clauses. See also
# https://wiki.archlinux.org/title/PKGBUILD#license
special_licenses = ["bsd", "isc", "libpng", "ofl", "mit", "python", "zlib"]


class package(TarballRule):
    name = "licensepkg"
    description = "Verifies license is included in a package file"

    def analyze(self, pkginfo, tar):
        common_licenses = [x.lower() for x in os.listdir("/usr/share/licenses/common")]
        need_licensefile = False

        if is_debug(pkginfo):
            return

        if not pkginfo.get("license"):
            self.errors.append(("missing-license", ()))
            return

        # Check all licenses for validity
        for license in pkginfo["license"]:
            lowerlicense, _, sublicense = license.lower().partition(":")
            # Custom licenses and licenses listed in special_licenses always need to ship a license file
            if lowerlicense == "custom" or lowerlicense in special_licenses:
                need_licensefile = True
            # Flag licenses that aren't in common/ and not marked as `custom`
            elif lowerlicense not in common_licenses:
                self.errors.append(("not-a-common-license %s", license))

        if need_licensefile:
            # Check if license dir is a symlink
            symlicensedir = next(
                filter((lambda f: f.name == "usr/share/licenses/" + pkginfo["name"] and f.issym()), tar), None
            )
            if symlicensedir:
                linklead = os.path.dirname(symlicensedir.name)
                # os.path.join drops the 1st arg if the 2nd one is absolute
                linkdest = os.path.join(linklead, symlicensedir.linkname)
                linkdest = os.path.normpath(linkdest).lstrip("/").rstrip("/")
                linkpkgname = os.path.basename(linkdest)
                # if the symlink points to licenses dir and the linked package is in depends,
                # then search license file in it
                if linkdest.startswith("usr/share/licenses/") and linkpkgname in pkginfo["depends"]:
                    linkpkginfo = load_from_db(linkpkgname)
                    if linkpkginfo:
                        pkginfo = linkpkginfo

            filenames = set(name.rstrip("/") for name, _, _ in pkginfo["files"])

            if "usr/share/licenses/" + pkginfo["name"] not in filenames:
                self.errors.append(("missing-custom-license-dir usr/share/licenses/%s", pkginfo["name"]))
            elif not any(filename.startswith("usr/share/licenses/" + pkginfo["name"] + "/") for filename in filenames):
                self.errors.append(("missing-custom-license-file usr/share/licenses/%s/*", pkginfo["name"]))
