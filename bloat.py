#!/usr/bin/env python3
#
# Copyright 2013 Google Inc. All Rights Reserved.
# Python 3 port + minor fixes.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""bloat.py (Python 3 port)

Generate webtreemap-compatible JSON summaries of binary size.

Typical workflow (assumes an ELF or Mach-O binary built with `-g`):

    # 1) produce symbol table:
    nm -C -S -l /path/to/binary > nm.out
    # 2) produce section table:
    objdump -h /path/to/binary > objdump.out
    # 3) render:
    ./bloat_py3.py --nm-output=nm.out syms > bloat.json
    ./bloat_py3.py --objdump-output=objdump.out sections > sections.json

NOTE for Windows / MSVC PE binaries (e.g. libcef.dll):
GNU nm/objdump can *read* PE files but they cannot read PDB debug info,
so `--nm-output` won't have per-symbol sizes or source paths for MSVC
builds. See the README for alternative tools (bloaty, SizeBench).
Use LLVM-flavoured nm/objdump for LLVM/lld-linked binaries.
"""

import argparse
import json
import operator
import os
import re
import subprocess
import sys


def format_bytes(n_bytes):
    """Pretty-print a number of bytes."""
    if n_bytes > 1e6:
        return '%.1fm' % (n_bytes / 1.0e6)
    if n_bytes > 1e3:
        return '%.1fk' % (n_bytes / 1.0e3)
    return str(n_bytes)


def symbol_type_to_human(sym_type):
    """Convert a symbol type as printed by nm into a human-readable name."""
    return {
        'b': 'bss',
        'd': 'data',
        'r': 'read-only data',
        't': 'code',
        'u': 'weak symbol',  # Unique global.
        'w': 'weak symbol',
        'v': 'weak symbol',
    }[sym_type]


def parse_nm(input_iter):
    """Parse nm output.

    Argument: an iterable over lines of nm output.

    Yields: (symbol name, symbol type, symbol size, source file path).
    Path may be None if nm couldn't figure out the source file.
    """
    # Match lines with size + symbol + optional filename.
    sym_re = re.compile(r'^[0-9a-f]+ ([0-9a-f]+) (.) ([^\t]+)(?:\t(.*):\d+)?$')
    # Match lines with addr but no size.
    addr_re = re.compile(r'^[0-9a-f]+ (.) ([^\t]+)(?:\t.*)?$')
    # Match lines that don't have an address at all -- typically external symbols.
    noaddr_re = re.compile(r'^ + (.) (.*)$')

    for line in input_iter:
        line = line.rstrip()
        match = sym_re.match(line)
        if match:
            size, sym_type, sym = match.groups()[0:3]
            size = int(size, 16)
            sym_type = sym_type.lower()
            if sym_type in ('u', 'v'):
                sym_type = 'w'  # just call them all weak
            if sym_type == 'b':
                continue  # skip all BSS for now
            path = match.group(4)
            yield sym, sym_type, size, path
            continue
        match = addr_re.match(line)
        if match:
            # No size == we don't care.
            continue
        match = noaddr_re.match(line)
        if match:
            sym_type, _ = match.groups()
            if sym_type in ('U', 'w'):
                # external or weak symbol
                continue

        print('unparsed:', repr(line), file=sys.stderr)


def demangle(ident, cppfilt):
    if cppfilt and ident.startswith('_Z'):
        # Demangle names when possible. Mangled names all start with _Z.
        out = subprocess.check_output([cppfilt, ident])
        if isinstance(out, bytes):
            out = out.decode('utf-8', errors='replace')
        ident = out.strip()
    return ident


class Suffix:
    def __init__(self, suffix, replacement):
        self.pattern = '^(.*)' + suffix + '(.*)$'
        self.re = re.compile(self.pattern)
        self.replacement = replacement


class SuffixCleanup:
    """Pre-compile suffix regular expressions."""

    def __init__(self):
        self.suffixes = [
            Suffix(r'\.part\.([0-9]+)', 'part'),
            Suffix(r'\.constprop\.([0-9]+)', 'constprop'),
            Suffix(r'\.isra\.([0-9]+)', 'isra'),
        ]

    def cleanup(self, ident, cppfilt):
        """Cleanup identifiers that have suffixes preventing demangling,
        and demangle if possible."""
        to_append = []
        for s in self.suffixes:
            found = s.re.match(ident)
            if not found:
                continue
            to_append += [' [' + s.replacement + '.' + found.group(2) + ']']
            ident = found.group(1) + found.group(3)
        if to_append:
            # Only try to demangle if there were suffixes.
            ident = demangle(ident, cppfilt)
        for s in to_append:
            ident += s
        return ident


suffix_cleanup = SuffixCleanup()


def parse_cpp_name(name, cppfilt):
    name = suffix_cleanup.cleanup(name, cppfilt)

    # Turn prefixes into suffixes so namespacing works.
    prefixes = [
        ['bool ', ''],
        ['construction vtable for ', ' [construction vtable]'],
        ['global constructors keyed to ', ' [global constructors]'],
        ['guard variable for ', ' [guard variable]'],
        ['int ', ''],
        ['non-virtual thunk to ', ' [non-virtual thunk]'],
        ['typeinfo for ', ' [typeinfo]'],
        ['typeinfo name for ', ' [typeinfo name]'],
        ['virtual thunk to ', ' [virtual thunk]'],
        ['void ', ''],
        ['vtable for ', ' [vtable]'],
        ['VTT for ', ' [VTT]'],
    ]
    for prefix, replacement in prefixes:
        if name.startswith(prefix):
            name = name[len(prefix):] + replacement
    # Simplify parenthesis parsing.
    replacements = [
        ['(anonymous namespace)', '[anonymous namespace]'],
    ]
    for value, replacement in replacements:
        name = name.replace(value, replacement)

    def parse_one(val):
        """Returns (leftmost-part, remaining)."""
        if (val.startswith('operator')
                and len(val) > 8
                and not (val[8].isalnum() or val[8] == '_')):
            # Operator overload function, terminate.
            return val, ''
        co = val.find('::')
        lt = val.find('<')
        pa = val.find('(')
        co = len(val) if co == -1 else co
        lt = len(val) if lt == -1 else lt
        pa = len(val) if pa == -1 else pa
        if co < lt and co < pa:
            # Namespace or type name.
            return val[:co], val[co + 2:]
        if lt < pa:
            # Template. Make sure we capture nested templates too.
            open_tmpl = 1
            gt = lt
            while gt < len(val) - 1 and (val[gt] != '>' or open_tmpl != 0):
                gt = gt + 1
                if gt < len(val) and val[gt] == '<':
                    open_tmpl = open_tmpl + 1
                if gt < len(val) and val[gt] == '>':
                    open_tmpl = open_tmpl - 1
            ret = val[gt + 1:]
            if ret.startswith('::'):
                ret = ret[2:]
            if ret.startswith('('):
                # Template function, terminate.
                return val, ''
            return val[:gt + 1], ret
        # Terminate with any function name, identifier, or unmangled name.
        return val, ''

    parts = []
    while name:
        (part, name) = parse_one(name)
        assert len(part) > 0
        parts.append(part)
    return parts


def treeify_syms(symbols, strip_prefix=None, cppfilt=None):
    dirs = {}
    for sym, sym_type, size, path in symbols:
        if path:
            path = os.path.normpath(path)
            if strip_prefix and path.startswith(strip_prefix):
                path = path[len(strip_prefix):]
            elif path.startswith('/'):
                path = path[1:]
            path = ['[path]'] + path.split('/')

        parts = parse_cpp_name(sym, cppfilt)
        if len(parts) == 1:
            if path:
                # No namespaces, group with path.
                parts = path + parts
            else:
                new_prefix = ['[ungrouped]']
                regroups = [
                    ['.L.str', '[str]'],
                    ['.L__PRETTY_FUNCTION__.', '[__PRETTY_FUNCTION__]'],
                    ['.L__func__.', '[__func__]'],
                    ['.Lswitch.table', '[switch table]'],
                ]
                for prefix, group in regroups:
                    if parts[0].startswith(prefix):
                        parts[0] = parts[0][len(prefix):]
                        parts[0] = demangle(parts[0], cppfilt)
                        new_prefix += [group]
                        break
                parts = new_prefix + parts

        key = parts.pop()
        tree = dirs
        try:
            depth = 0
            for part in parts:
                depth += 1
                assert part != '', path
                if part not in tree:
                    tree[part] = {'$bloat_symbols': {}}
                if sym_type not in tree[part]['$bloat_symbols']:
                    tree[part]['$bloat_symbols'][sym_type] = 0
                tree[part]['$bloat_symbols'][sym_type] += 1
                tree = tree[part]
            old_size, old_symbols = tree.get(key, (0, {}))
            if sym_type not in old_symbols:
                old_symbols[sym_type] = 0
            old_symbols[sym_type] += 1
            tree[key] = (old_size + size, old_symbols)
        except Exception:
            print('sym `%s`\tparts `%s`\tkey `%s`' % (sym, parts, key),
                  file=sys.stderr)
            raise
    return dirs


def jsonify_tree(tree, name):
    children = []
    total = 0

    for key, val in tree.items():
        if key == '$bloat_symbols':
            continue
        if isinstance(val, dict):
            subtree = jsonify_tree(val, key)
            total += subtree['data']['$area']
            children.append(subtree)
        else:
            (size, symbols) = val
            total += size
            # Original assertion was buggy; simplify: pick the first symbol type.
            symbol_key = next(iter(symbols.keys()))
            symbol = symbol_type_to_human(symbol_key)
            children.append({
                'name': key + ' ' + format_bytes(size),
                'data': {
                    '$area': size,
                    '$symbol': symbol,
                },
            })

    children.sort(key=lambda child: -child['data']['$area'])
    dominant_symbol = ''
    if '$bloat_symbols' in tree:
        dominant_symbol = symbol_type_to_human(
            max(tree['$bloat_symbols'].items(),
                key=operator.itemgetter(1))[0])
    return {
        'name': name + ' ' + format_bytes(total),
        'data': {
            '$area': total,
            '$dominant_symbol': dominant_symbol,
        },
        'children': children,
    }


def dump_nm(nmfile, strip_prefix, cppfilt):
    dirs = treeify_syms(parse_nm(nmfile), strip_prefix, cppfilt)
    print('var kTree = '
          + json.dumps(jsonify_tree(dirs, '[everything]'), indent=2))


def parse_objdump(input_iter):
    """Parse objdump -h output."""
    sec_re = re.compile(r'^\d+ (\S+) +([0-9a-z]+)')
    sections = []
    debug_sections = []

    for line in input_iter:
        line = line.strip()
        match = sec_re.match(line)
        if match:
            name, size = match.groups()
            if name.startswith('.'):
                name = name[1:]
            if name.startswith('debug_'):
                name = name[len('debug_'):]
                debug_sections.append((name, int(size, 16)))
            else:
                sections.append((name, int(size, 16)))
            continue
    return sections, debug_sections


def jsonify_sections(name, sections):
    children = []
    total = 0
    for section, size in sections:
        children.append({
            'name': section + ' ' + format_bytes(size),
            'data': {'$area': size},
        })
        total += size

    children.sort(key=lambda child: -child['data']['$area'])

    return {
        'name': name + ' ' + format_bytes(total),
        'data': {'$area': total},
        'children': children,
    }


def dump_sections(objdump):
    sections, debug_sections = parse_objdump(objdump)
    sections_j = jsonify_sections('sections', sections)
    debug_sections_j = jsonify_sections('debug', debug_sections)
    size = sections_j['data']['$area'] + debug_sections_j['data']['$area']
    print('var kTree = ' + json.dumps({
        'name': 'top ' + format_bytes(size),
        'data': {'$area': size},
        'children': [debug_sections_j, sections_j],
    }))


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('mode', choices=['syms', 'dump', 'sections'],
                        help='syms=treemap JSON, dump=size-sorted text, '
                             'sections=sections treemap JSON')
    parser.add_argument('--nm-output', dest='nmpath', default='nm.out',
                        help='path to nm output [default=nm.out]')
    parser.add_argument('--objdump-output', dest='objdumppath',
                        default='objdump.out',
                        help='path to objdump output [default=objdump.out]')
    parser.add_argument('--strip-prefix',
                        help='strip PATH prefix from paths; '
                             'e.g. /path/to/src/root')
    parser.add_argument('--filter',
                        help='include only symbols/files matching FILTER')
    parser.add_argument('--c++filt', dest='cppfilt', default='c++filt',
                        help="Path to c++filt, used to demangle symbols that "
                             "weren't handled by nm. Set to an invalid path "
                             "to disable.")
    opts = parser.parse_args()

    mode = opts.mode
    if mode == 'syms':
        try:
            res = subprocess.check_output([opts.cppfilt, 'main'])
            if isinstance(res, bytes):
                res = res.decode('utf-8', errors='replace')
            if res.strip() != 'main':
                print("%s failed demangling, output won't be demangled."
                      % opts.cppfilt, file=sys.stderr)
                opts.cppfilt = None
        except Exception:
            print("Could not find c++filt at %s, output won't be demangled."
                  % opts.cppfilt, file=sys.stderr)
            opts.cppfilt = None
        with open(opts.nmpath, 'r', encoding='utf-8', errors='replace') as nmfile:
            dump_nm(nmfile, strip_prefix=opts.strip_prefix,
                    cppfilt=opts.cppfilt)
    elif mode == 'sections':
        with open(opts.objdumppath, 'r', encoding='utf-8',
                  errors='replace') as objdumpfile:
            dump_sections(objdumpfile)
    elif mode == 'dump':
        with open(opts.nmpath, 'r', encoding='utf-8',
                  errors='replace') as nmfile:
            syms = list(parse_nm(nmfile))
        # a list of (sym, type, size, path); sort by size.
        syms.sort(key=lambda x: -x[2])
        total = 0
        for sym, sym_type, size, path in syms:
            if sym_type in ('b', 'w'):
                continue  # skip bss and weak symbols
            if path is None:
                path = ''
            if opts.filter and not (opts.filter in sym or opts.filter in path):
                continue
            print('%6s %s (%s) %s' % (format_bytes(size), sym,
                                      symbol_type_to_human(sym_type), path))
            total += size
        print('%6s %s' % (format_bytes(total), 'total'))


if __name__ == '__main__':
    main()
