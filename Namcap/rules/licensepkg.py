# Copyright (C) 2003-2023 Namcap contributors, see AUTHORS for details.
# SPDX-License-Identifier: GPL-2.0-or-later

from license_expression import BaseSymbol, LicenseSymbol, LicenseWithExceptionSymbol, get_spdx_licensing
from Namcap.ruleclass import TarballRule
from Namcap.package import load_from_db
from Namcap.util import is_debug
from pathlib import Path
from tarfile import TarFile, TarInfo


def get_license_canonicalized(license: str) -> str:
    """Get the canonicalized form of a license string

    This function may raise an Exception if it's not possible to derive any meaning from the input string
    """
    licensing = get_spdx_licensing()
    return str(licensing.parse(license, strict=True))


def get_license_symbols(license: str) -> set[BaseSymbol]:
    """Extract all license symbols from a license string

    This function may raise an Exception if it's not possible to derive any meaning from the input string.
    This may be due to being unable to parse the string at all or if a license exception in the string is not a valid
    SPDX license exception identifier.
    """
    licensing = get_spdx_licensing()
    symbols = licensing.parse(license, strict=True)
    return symbols.symbols


def get_uncommon_license_symbols(licenses: set[BaseSymbol]) -> set[BaseSymbol]:
    """Get a set of all uncommon license symbols (those that require a custom file)

    This function compares against all common SPDX license files.
    When encountering LicenseWithExceptionSymbols, both the LicenseSymbol and the exception are checked.
    """
    common_spdx_licenses = [f"{x.stem}" for x in sorted(Path("/usr/share/licenses/spdx/").glob("*.txt")) if x.is_file()]

    uncommon_symbols: list[BaseSymbol] = []
    for symbol in licenses:
        # if the symbol also carries an exception only match against the license symbol
        if isinstance(symbol, LicenseWithExceptionSymbol):
            if str(list(symbol.decompose())[0]) not in common_spdx_licenses:
                uncommon_symbols.append(list(symbol.decompose())[0])
            if str(list(symbol.decompose())[1]) not in common_spdx_licenses:
                uncommon_symbols.append(list(symbol.decompose())[1])
        else:
            if str(symbol) not in common_spdx_licenses:
                uncommon_symbols.append(symbol)

    return set(uncommon_symbols)


def get_unknown_license_symbols(licenses: set[BaseSymbol]) -> set[BaseSymbol]:
    """Get a set of all unknown license symbols

    This function ignores LicenseSymbols that describe a license exception, when comparing against all known SPDX
    license identifiers.
    """
    all_spdx_licenses: list[str] = []

    with open("/usr/share/licenses/known_spdx_license_identifiers.txt") as file:
        while line := file.readline():
            all_spdx_licenses.append(LicenseSymbol(line.rstrip("\n")))

    unknown_symbols: list[BaseSymbol] = []
    for symbol in licenses:
        # if the symbol also carries an exception only match against the license symbol
        if isinstance(symbol, LicenseWithExceptionSymbol):
            if str(list(symbol.decompose())[0]) not in [str(license) for license in all_spdx_licenses]:
                unknown_symbols.append(symbol)
        else:
            if str(symbol) not in [str(license) for license in all_spdx_licenses]:
                unknown_symbols.append(symbol)

    return set(unknown_symbols)


def get_symlink_target(member: TarInfo) -> str:
    """Return the symlink target of a TarInfo

    Absolute symlink targets will be returned as relative Path strings, as we are using them to search for files in
    TarFile objects (and all their members are relative).

    :raises: ValueError if the link target has an invalid amount of upward change dirs.
    """
    symlink_target: str
    if Path(member.linkname).is_absolute():
        symlink_target = str(Path(member.linkname.lstrip("/")))
    else:
        parents = Path(member.linkname).parts.count("..")
        reduce_name_by = -1 - parents

        # if we change dir upwards from the file name too often we may escape the original name and that's not valid
        if (len(Path(member.name).parts) + reduce_name_by) < 0:
            raise ValueError(f"Can not change dir upwards: {member.name} -> {member.linkname}")

        base_parts = Path(member.name).parts[0:reduce_name_by]
        add_parts = tuple(filter(lambda x: x != "..", Path(member.linkname).parts))
        symlink_target = str(Path("/".join(base_parts + add_parts)))

    return symlink_target


def package_license_files(tar: TarFile | None, pkgname: str) -> tuple[dict[str, str], str | None]:
    """Return the license files referenced in a package and whether the license dir is a symlink"""
    license_dir_symlink = None
    files: dict[str, str] = {}

    if not tar:
        return (files, license_dir_symlink)

    for member in tar.getmembers():
        # check if entire /usr/share/license/{pkgname}/ dir is a symlink
        if member.issym() and member.name == f"usr/share/licenses/{pkgname}":
            try:
                license_dir_symlink = get_symlink_target(member)
            except ValueError:
                continue
            else:
                break
        # the license is a file
        if (
            member.isfile()
            and not member.issym()
            and member.name.startswith(f"usr/share/licenses/{pkgname}/")
            and member.name != f"usr/share/licenses/{pkgname}"
        ):
            files[member.name] = True
        # the license is a symlink, we'll check later
        if member.issym() and member.name.startswith(f"usr/share/licenses/{pkgname}/"):
            try:
                files[get_symlink_target(member)] = False
            except ValueError:
                continue

    # check existence of all symlinked files
    for file, exists in [(file, exists) for (file, exists) in files.items() if not exists]:
        for member in tar.getmembers():
            if member.isfile() and not member.issym() and member.name == file:
                files[file] = True

    # if license dir is a symlink, add all files below the targeted license dir to files dict
    if license_dir_symlink:
        for member in tar.getmembers():
            if member.isfile() and not member.issym() and member.name.startswith(license_dir_symlink):
                files[member.name] = True

    return (files, license_dir_symlink)


class package(TarballRule):
    name = "licensepkg"
    description = "Verifies license is included in a package file"

    def analyze(self, pkginfo, tar: TarFile | None):
        # return early, as we do not check debug packages
        if is_debug(pkginfo):
            return

        # error and return early if there is no license
        if not pkginfo.get("license"):
            self.errors.append(("missing-license", ()))
            return

        # get canonicalized form of all license strings (and add errors for them)
        for license in pkginfo["license"]:
            try:
                canonicalized_license = get_license_canonicalized(license)
            except Exception:
                # we pass here, as we call get_license_symbols() later, which will raise as well
                pass
            else:
                if license != canonicalized_license:
                    self.errors.append(("license-statement-formatting %s %s", (license, canonicalized_license)))

        # get a combined set of all license symbols from all license strings
        # the license symbols may be of type LicenseSymbol (license) or LicenseWithExceptionSymbol (license + exception)
        license_symbols: set[BaseSymbol] = set()
        for license in pkginfo["license"]:
            try:
                new_license_symbols = get_license_symbols(license)
            except Exception:
                self.errors.append(("invalid-license-string %s", tuple([license])))
            else:
                license_symbols.update(new_license_symbols)

        # check if any license (ignoring exception) symbols are unknown (and add errors for them, if they are not prefixed with LicenseRef-)
        for license in get_unknown_license_symbols(license_symbols):
            if not str(license).startswith("LicenseRef-"):
                self.errors.append(("unknown-spdx-license-identifier %s", tuple([str(license)])))

        # check whether there is a discrepancy between uncommon license symbols and license files found in the package
        uncommon_license_symbols = get_uncommon_license_symbols(license_symbols)
        if len(uncommon_license_symbols) == 0:
            return

        (pkg_licenses, license_dir_symlink) = package_license_files(tar, pkginfo["name"])
        licenses_in_pkg = len([(file, exists) for (file, exists) in pkg_licenses.items() if exists])
        licenses_outside_pkg = len([(file, exists) for (file, exists) in pkg_licenses.items() if not exists])

        # there are not enough license files in the package's license directory
        if licenses_in_pkg < len(uncommon_license_symbols) and licenses_outside_pkg == 0 and not license_dir_symlink:
            self.errors.append(
                (
                    "license-file-missing %s %s %s",
                    (
                        str(", ".join([str(id) for id in list(uncommon_license_symbols)])),
                        pkginfo["name"],
                        f"{licenses_in_pkg}/{len(uncommon_license_symbols)}",
                    ),
                )
            )

        # there are symlinks for license files that point to files in external packages
        if licenses_in_pkg == 0 and licenses_outside_pkg > 0 and not license_dir_symlink:
            outbound_licenses = [license for (license, exists) in pkg_licenses.items() if not exists]
            self.warnings.append(("license-file-in-external-pkg %s", tuple([", ".join(outbound_licenses)])))

            for other_pkg in [load_from_db(name) for name in pkginfo["depends"]]:
                for outbound_license in outbound_licenses:
                    if outbound_license in other_pkg["files"]:
                        pkg_licenses[outbound_license] = True
                        # if there are no license files left to check, break early
                        if not [license for (license, exists) in pkg_licenses.items() if not exists]:
                            break

            outbound_licenses = [license for (license, exists) in pkg_licenses.items() if not exists]
            # there are symlinks to license files in other pkgs, but those files are missing (or the package in question is not a dependency)
            for outbound_license in outbound_licenses:
                self.errors.append(
                    (
                        "license-file-missing-in-other-pkg %s",
                        tuple([outbound_license]),
                    )
                )

        # the license dir is a symlink which points to another package
        if licenses_in_pkg == 0 and licenses_outside_pkg == 0 and license_dir_symlink:
            self.warnings.append(("license-dir-in-external-pkg %s", tuple([license_dir_symlink])))

            # try to figure out which other package contains the actual files
            other_pkg = (
                list(Path(license_dir_symlink.lstrip("usr/share/licenses/")).parts)[0]
                if license_dir_symlink.startswith("usr/share/licenses/")
                else None
            )
            if other_pkg:
                if other_pkg not in pkginfo["depends"]:
                    self.errors.append(
                        (
                            "license-dir-target-pkg-not-in-depends %s %s %s",
                            (
                                other_pkg,
                                str(", ".join([str(id) for id in list(uncommon_license_symbols)])),
                                f"0/{len(uncommon_license_symbols)}",
                            ),
                        )
                    )
                    return

                other_pkg_info = load_from_db(other_pkg)
                for file in other_pkg_info["files"]:
                    if file.startswith(license_dir_symlink) and file != license_dir_symlink:
                        licenses_outside_pkg += 1
            else:
                for other_pkg_info in [load_from_db(name) for name in pkginfo["depends"]]:
                    for file, _, _ in other_pkg_info["files"]:
                        if file.startswith(license_dir_symlink) and file != license_dir_symlink:
                            licenses_outside_pkg += 1

            # there are still some files missing
            if licenses_outside_pkg < len(uncommon_license_symbols):
                self.errors.append(
                    (
                        "license-dir-is-symlink-and-license-files-missing %s %s %s",
                        (
                            str(", ".join([str(id) for id in list(uncommon_license_symbols)])),
                            license_dir_symlink,
                            f"{licenses_outside_pkg}/{len(uncommon_license_symbols)}",
                        ),
                    )
                )
