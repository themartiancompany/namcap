#!/usr/bin/env python3
# Copyright (C) 2003-2023 Namcap contributors, see AUTHORS for details.
# SPDX-License-Identifier: GPL-2.0-or-later

import getopt
import os
import sys
import tarfile

import Namcap.depends
import Namcap.rules
import Namcap.tags
import Namcap.version


# Functions
def get_modules():
    """Return all possible modules (rules)"""
    return Namcap.rules.all_rules


def get_enabled_modules():
    """Return modules (rules) that should be used by default"""
    return dict(filter(lambda x: x[1].enable, get_modules().items()))


def usage():
    """Display usage information"""
    print("")
    print("Usage: " + sys.argv[0] + " [OPTIONS] packages")
    print("")
    print("Options are:")
    print("    -L, --list                       : list available rules")
    print("    -i                               : prints information (debug) responses from rules")
    print("    -m                               : makes the output parseable (machine-readable)")
    print("    -e rulelist, --exclude=rulelist  : don't apply RULELIST rules to the package")
    print("    -r rulelist, --rules=rulelist    : only apply RULELIST rules to the package")
    print("    -t tags                          : use a custom tag file")
    print("    -v version                       : print version and exit")

    sys.exit(2)


def open_package(filename):
    try:
        tar = tarfile.open(filename, "r")
        if ".PKGINFO" not in tar.getnames():
            tar.close()
            return None
    except IOError:
        if tar:
            tar.close()
        return None
    return tar


def check_rules_exclude(optlist):
    """Check if the -r (--rules) and the -r (--exclude) options
    are being used at same time"""
    args_used = 0
    for i in optlist:
        if "-r" in i or "-e" in i:
            args_used += 1
        if "--rules" in i or "--exclude" in i:
            args_used += 1
    return args_used


def show_messages(name, key, messages):
    colored_key = {
        "E": "\033[91mE\033[00m",
        "W": "\033[93mW\033[00m",
        "I": "\033[92mI\033[00m",
    }
    for msg in messages:
        if sys.stdout.isatty():
            print("%s %s: %s" % (name, colored_key[key], Namcap.tags.format_message(msg)))
        else:
            print("%s %s: %s" % (name, key, Namcap.tags.format_message(msg)))


def process_realpackage(package, modules):
    """Runs namcap checks over a package tarball"""
    pkgtar = open_package(package)

    if not pkgtar:
        print("Error: %s is empty or is not a valid package" % package)
        return 1

    pkginfo = Namcap.package.load_from_tarball(package)
    # Loop through each one, load them apply if possible
    for i in modules:
        rule = get_modules()[i]()

        if isinstance(rule, Namcap.ruleclass.PkgInfoRule):
            rule.analyze(pkginfo, None)
        elif isinstance(rule, Namcap.ruleclass.PkgbuildRule):
            pass
        elif isinstance(rule, Namcap.ruleclass.TarballRule):
            rule.analyze(pkginfo, pkgtar)
        else:
            show_messages(pkginfo["name"], "E", [("error-running-rule %s", i)])

        # Output the three types of messages
        show_messages(pkginfo["name"], "E", rule.errors)
        show_messages(pkginfo["name"], "W", rule.warnings)
        if info_reporting:
            show_messages(pkginfo["name"], "I", rule.infos)

    # dependency analysis
    errs, warns, infos = Namcap.depends.analyze_depends(pkginfo)
    show_messages(pkginfo["name"], "E", errs)
    show_messages(pkginfo["name"], "W", warns)
    if info_reporting:
        show_messages(pkginfo["name"], "I", infos)


def process_pkginfo(pkginfo, modules):
    """Runs namcap checks of a single, non-split PacmanPackage object"""
    for i in modules:
        rule = get_modules()[i]()
        if isinstance(rule, Namcap.ruleclass.PkgInfoRule):
            rule.analyze(pkginfo, None)

        # Output the messages
        if "base" in pkginfo:
            name = "PKGBUILD (" + pkginfo["base"] + ")"
        else:
            name = "PKGBUILD (" + pkginfo["name"] + ")"
        show_messages(name, "E", rule.errors)
        show_messages(name, "W", rule.warnings)
        if info_reporting:
            show_messages(name, "I", rule.infos)


def process_pkgbuild(package, modules):
    """Runs namcap checks over a PKGBUILD"""
    # We might want to do some verifying in here... but really... isn't that
    # what pacman.load is for?
    pkginfo = Namcap.package.load_from_pkgbuild(package)

    if pkginfo is None:
        print("Error: %s is not a valid PKGBUILD" % package)
        return 1

    # apply global PKGBUILD rules
    for i in modules:
        rule = get_modules()[i]()
        if isinstance(rule, Namcap.ruleclass.PkgbuildRule):
            rule.analyze(pkginfo, package)
        # Output the messages
        if "base" in pkginfo:
            name = "PKGBUILD (" + pkginfo["base"] + ")"
        else:
            name = "PKGBUILD (" + pkginfo["name"] + ")"
        show_messages(name, "E", rule.errors)
        show_messages(name, "W", rule.warnings)
        if info_reporting:
            show_messages(name, "I", rule.infos)
    # apply per pkginfo rule
    for subpkg in pkginfo.subpackages if pkginfo.is_split else [pkginfo]:
        process_pkginfo(subpkg, modules)


# Main
modules = get_modules()
info_reporting = 0
machine_readable = False
filename = None

# get our options and process them
try:
    optlist, args = getopt.getopt(
        sys.argv[1:],
        "ihmr:e:t:Lv",
        [
            "info",
            "help",
            "machine-readable",
            "rules=",
            "exclude=",
            "tags=",
            "list",
            "version",
        ],
    )
except getopt.GetoptError:
    usage()

active_modules = {}

# Verifying if we are using the -r and -r options at same time
if check_rules_exclude(optlist) > 1:
    print("You cannot use '-r' (--rules) and '-e' (-exclude) options at same time")
    usage()

for i, k in optlist:
    if i in ("-L", "--list"):
        print("-" * 20 + " Namcap rule list " + "-" * 20)
        for j in sorted(modules):
            print("%-20s: %s" % (j, modules[j].description))
        sys.exit(2)

    if i in ("-r", "--rules"):
        module_list = k.split(",")
        for j in module_list:
            if j in modules:
                active_modules[j] = modules[j]
            else:
                print("Error: Rule '%s' does not exist" % j)
                usage()

    # Used to exclude some rules from the check
    if i in ("-e", "--exclude"):
        module_list = k.split(",")
        active_modules.update(modules)
        for j in module_list:
            if j in modules:
                active_modules.pop(j)
            else:
                print("Error: Rule '%s' does not exist" % j)
                usage()

    if i in ("-i", "--info"):
        info_reporting = 1

    if i in ("-h", "--help"):
        usage()
    if i in ("-m", "--machine-readable"):
        machine_readable = True

    if i in ("-t", "--tags"):
        filename = k

    if i in ("-v", "--version"):
        print(Namcap.version.get_version())
        sys.exit(0)

# If there are no args, print usage
if args == []:
    usage()

Namcap.tags.load_tags(filename=filename, machine=machine_readable)

packages = args

# No rules selected?  Then use default selection
if len(active_modules) == 0:
    active_modules = get_enabled_modules()

# Go through each package, get the info, and apply the rules
for package in packages:
    if not os.access(package, os.R_OK):
        print("Error: Problem reading %s" % package)
        usage()

    if os.path.isfile(package) and tarfile.is_tarfile(package):
        process_realpackage(package, active_modules)
    elif "PKGBUILD" in package:
        process_pkgbuild(package, active_modules)
    else:
        print("Error: %s not package or PKGBUILD" % package)
