# Information Discovery
# 
# Copyright 2018 Carnegie Mellon University. All Rights Reserved.
# 
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
# IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
# FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
# OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
# MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a BSD-style license, please see LICENSE.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution. Please see Copyright notice for
# non-US Government use and distribution.
#
# CERT is registered in the U.S. Patent and Trademark Office by
# Carnegie Mellon University.
#
# DM18-0345

#from __future__ import print_function

import re, sys

def re_str_from_tokens(tokens):
    """
    Constructs an optimmized matching regular expression from a list
    of tokens.
    """
    parts = _re_components_from_trie(_make_trie(tokens))
    for i, x in enumerate(parts):
        parts[i] = re.sub(r"(\\\s)+", r"\s+", x)
        if '|' in parts[i]:
            parts[i] = "(?:%s)" % parts[i]
    return r"(?:%s)" % '|'.join(parts)

TRIE_END = ''

def _make_trie(tokens):
    root = {}
    for token in tokens:
        cur = root
        for x in _atomize_token(token):
            cur = cur.setdefault(x, {})
        cur.setdefault(TRIE_END, TRIE_END)
    return root

def _re_components_from_trie(trie):
    prefixes = []
    for char in sorted(trie.keys()):
        if char == TRIE_END:
            continue
        prefix = char
        t = trie[char]
        while len(t) == 1:
            char = list(t.keys())[0]
            if char == TRIE_END:
                t = TRIE_END
                break
            else:
                prefix += char
                t = t[char]
        if t == TRIE_END:
            prefixes.append(prefix)
        else:
            suffixes = sorted(_re_components_from_trie(t),
                              key=lambda x: -len(x))
            if len(suffixes) == 1:
                if TRIE_END in t:
                    #print("LEAF", prefix)
                    if len(suffixes[0]) == 1:
                        prefixes.append("%s%s?" % (prefix, suffixes[0]))
                    else:
                        prefixes.append("%s(?:%s)?" % (prefix, suffixes[0]))
                else:
                    # this shouldn't happen
                    prefixes.append("%s%s" % (prefix, suffixes[0]))
            else:
                suffixes = '|'.join(suffixes)
                if TRIE_END in t:
                    #print("LEAF", prefix)
                    prefixes.append("%s(?:%s)?" % (prefix, suffixes))
                else:
                    prefixes.append("%s(?:%s)" % (prefix, suffixes))
    return prefixes

def _atomize_token(token):
    """
    Break token into glyphs, preserving regex constructs
    """
    assert re.compile(r"%s" % token)
    atom = ''
    escape = False
    bracket = False
    depth = 0
    for char in token:
        if escape:
            atom += char
            escape = False
            continue
        if char == '\\':
            if bracket or depth:
                atom += char
            else:
                yield atom
                atom = char
            escape = True
            continue
        if re.match(r"[{\*\?+]", char):
            atom += char
            continue
        if '{' in atom and '}' not in atom:
            atom += char
            continue
        if char == '[':
            if not depth:
                yield atom
                atom = char
            else:
                atom += char
            bracket = True
            continue
        if '[' in atom and ']' not in atom:
            atom += char
            continue
        if char == '(':
            if not depth:
                yield atom
                atom = char
            else:
                atom += char
            depth += 1
            continue
        if char == ')':
            depth -= 1
            atom += char
            continue
        if depth:
            atom += char
            continue
        if atom:
            yield atom
        atom = char
    yield atom
