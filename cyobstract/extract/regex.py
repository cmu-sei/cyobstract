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

from future import standard_library
standard_library.install_aliases()

import re, urllib.request, urllib.error, urllib.parse, urllib.parse

from . import re_auto

def create_master_regexes_dict():
    '''
    :return: A huge dict of all kinds of regexes, some being functions and some being simple compiled re regex expressions
    '''
    # Regular expressions used to match observable types
    regexes = {}

    # regular expression components
    primitives = {}

    # gets used in some case sensitive regexes, hence DOT
    primitives["dot"] = r"""
        (?:
           # asymmetric brackets ok
             [\[\(<{]  (?: \. | dot | DOT ) [\]\)>}]?
           | [\[\(<{]? (?: \. | dot | DOT ) [\]\)>}]
           | [\[\(<{] [dD] [\]\)>}]
           # spaces must both be present
           | \s (?: \. | dot | DOT ) \s
           # plain dot has to come last
           | (?: \. | dot | DOT )
        )
    """

    primitives["colon"] = r"""
        (?:
         # asymmetric brackets AND asymmetric spaces ok
         [\[\(<{\s]? (?: : | colon | COLON ) [\]\)>}\s]?
        )
    """

    primitives["at"] = r"""
        (?:
         # no spaces, too many false positives
         # symmetrical brackets or none at all
         @ | [\[\(<{] (?: @ | at | AT ) [\]\)>}]
        )
    """

    primitives["quad"] = r"""
        (?:
           25[0-5]
         | 2[0-4][0-9]
         | 1[0-9][0-9]
         | [1-9][0-9]
         | [0-9]
        )
    """

    primitives["ipv4"] = r"""
        %(quad)s %(dot)s %(quad)s %(dot)s %(quad)s %(dot)s %(quad)s
    """ % primitives

    # IP Version 4 addresses
    regexes["ipv4addr"] = re.compile(r"\b ( %(ipv4)s ) \b" % primitives, re.I|re.X)

    # IP Version 6 addresses

    primitives["octet"] = r"[0-9a-f]{1,4}"

    # no need to use %(colon)s for this; it gets false positives and
    # defanged forms aren't used for ipv6 in practice
    primitives["ipv6"] = r"""
        (?:
          (?: %(octet)s : ){7}
          (?: %(octet)s
           |  :
          )
        |
          (?: %(octet)s : ){6}
          (?: : %(octet)s
           |  %(ipv4)s
           |  :
          )
        |
          (?: %(octet)s : ){5}
          (?: (?: : %(octet)s ){1,2}
           |  : %(ipv4)s
           |  :
          )
        |
          (?: %(octet)s : ){4}
          (?: (?: : %(octet)s ){1,3}
           |  (?: : %(octet)s )? : %(ipv4)s
           |  :
          )
        |
          (?: %(octet)s : ){3}
          (?: (?: : %(octet)s ){1,4}
           |  (?: : %(octet)s ){0,2} : %(ipv4)s
           |  :
          )
        |
          (?: %(octet)s : ){2}
          (?: (?: : %(octet)s ){1,5}
           |  (?: : %(octet)s ){0,3} : %(ipv4)s
           |  :
          )
        |
          (?: %(octet)s : ){1}
          (?: (?: : %(octet)s ){1,6}
           |  (?: : %(octet)s ){0,4} : %(ipv4)s
           |  :
          )
        |
          :
          (?: (?: : %(octet)s ){1,7}
           |  (?: : %(octet)s ){0,5} : %(ipv4)s
           |  :
          )
        )
    """ % primitives

    regexes["ipv6addr"] = re.compile(r"\b ( %(ipv6)s ) \b" % primitives, re.I|re.X)

    regexes["ipv4range"] = re.compile(r"""
        \b( %(ipv4)s \s*-\s* %(ipv4)s )\b
    """ % primitives, re.X)

    regexes["ipv6range"] = re.compile(r"""
        \b( %(ipv6)s \s*-\s* %(ipv6)s )\b
    """ % primitives, re.I|re.X)

    primitives["ipv4cidr"] = r"""
        %(ipv4)s / (?: [0-9] | [1-2][0-9] | 3[0-2] )
    """ % primitives

    regexes["ipv4cidr"] = re.compile(r"\b( %(ipv4cidr)s )\b" % primitives, re.X)

    regexes["ipv6cidr"] = re.compile(r"""
        \b( %(ipv6)s / (?: \d | \d\d | 1[0-1]\d | 12[0-8] ) )\b
    """ % primitives, re.I|re.X)

    # ASNs
    # not case insensitive, otherwise grabs "as ..."
    primitives["asn"] = r"""
        ASN?(?:\s+Number)?
        \s*[\W|_]?\s*
        \d+
        (?:\.\d+)?
    """

    _asn_pat = re.compile(r"\b( %(asn)s )\b" % primitives, re.X)

    def extract_asn(text):
        for asn in _asn_pat.findall(text):
            # make sure ASN isn't in a reserved block or invalid
            num = int(re.search(r"(\d+)", asn).group(1))
            if (num >= 1 and num <= 23455) or \
               (num >= 23457 and num <= 64534) or \
               (num >= 131072 and num <= 4199999999):
                yield asn

    regexes["asn"] = extract_asn

    # tld regex build by bin/build_tld_re
    primitives["tld"] = re_auto.tld

    # FQDN
    primitives["fqdn"] = r"""
        (?:
         (?: [a-zA-Z0-9][a-zA-Z0-9\-_]* %(dot)s )+  # subdomains
         (?: %(tld)s )  # TLD
        )
    """ % primitives

    # case sensitive so TLD is all lower or all upper
    _fqdn_pat = re.compile(r"\b ( %(fqdn)s ) \b" % primitives, re.X)
    _fqdn_split_pat = re.compile(r"%(dot)s" % primitives, re.X)

    def extract_fqdn(text):
        for dom in _fqdn_pat.findall(text):
            parts = _fqdn_split_pat.split(dom)
            if len(parts) == 2 and len(parts[0]) == 1:
                continue
            if all(len(x) == 2 for x in parts):
                continue
            if len(dom) > 160:
                continue
            yield dom

    regexes["fqdn"] = extract_fqdn

    # RFC 821 email addresses (note: "%%" due to format with primitives)
    regexes["email"] = re.compile(r"""
        \b
        (
         [a-z0-9] (?: [a-z0-9\._%%+\-]+ )?  # username
         %(at)s
         (?: %(fqdn)s | %(ipv4)s )
        )
        \b
    """ % primitives, re.I|re.X)

    # File extension-defined suspicious file types
    primitives["fileexts"] = re_auto.file_exts

    primitives["filename"] = r"""
        (?:
         # the chars starting with \s are technically allowed, but they
         # generate too many false positives
         [^/\\:*?"<>|\s`':;=]+
         %(dot)s %(fileexts)s
        )\b
    """ % primitives

    _ends_with_file_ext_pat = re.compile(r"""
        %(dot)s (%(fileexts)s) $
    """ % primitives, re.X)

    _filename_pat = re.compile(r"""
        ( %(filename)s )\b
    """ % primitives, re.X) # not case insensitive

    primitives["filename_promisc_ng"] = r"""
        (?:
         # the chars after | are technically allowed
         [^/\\:*?"<>|:;=\n]+?
         %(dot)s %(fileexts)s
        )\b
    """ % primitives

    primitives["filename_promisc"] = r"""
        (?:
         # the chars after | are technically allowed
         [^/\\:*?"<>|:;=\n]+
         %(dot)s %(fileexts)s
        )\b
    """ % primitives

    _filename_promisc_pat = re.compile(r"""
        \s*( %(filename_promisc)s )\b
    """ % primitives, re.I|re.X)

    _quoted_file_pat = re.compile(r'''
        "(%(filename_promisc)s)"
    ''' % primitives, re.I|re.X)

    # make sure last one ends with file extension
    _attachment_line_pat = re.compile(r"""
        \b (?: (?:Attachments? | File)(?:\s*names?)? ): \s* (.* \.%(fileexts)s) \s*$
    """ % primitives, re.I|re.X|re.MULTILINE)
    # for catching Attachments: blah_one.ext and blah_two.ext
    _attachment_and_list_pat = re.compile(r"""
        (%(dot)s %(fileexts)s) \s+ (?: & | and ) \s+
    """ % primitives, re.I|re.X)

    def extract_filenames(text):
        attachments = set()
        for line in _attachment_line_pat.findall(text):
            line = _attachment_and_list_pat.sub(r"\1 ; ", line)
            for f in re.split(r"\s*(?:;|,)\s*", line):
                m = _filename_promisc_pat.search(f)
                if m:
                    f = m.group(1)
                    if len(f) <= 70:
                        attachments.add(f)
                        yield f
        for f in _quoted_file_pat.findall(text):
            attachments.add(f.strip())
            yield f
        for f in _filename_pat.findall(text):
            if f in attachments:
                continue
            if f.endswith("dotdeb"):
                continue
            elif f == "SV.SO":
                continue
            if re.search(r"^[\[({]", f) and not re.search(r"[\])}]", f):
                # lots of filenames are parenthesized
                f = f[1:]
                if not _filename_pat.search(f):
                    # only a file ext remains
                    continue
            if attachments:
                try:
                    fp = re.compile(r"%s$" % re.escape(f))
                    for fa in attachments:
                        if fp.search(fa):
                            raise StopIteration
                except StopIteration:
                    # filename is fragment/match of an attachment
                    continue
            # unescape url fragments
            if '%' in f:
                x = None
                while f != x:
                    x = f
                    f = urllib.parse.unquote(x)
                for ff in _filename_promisc_pat.findall(f):
                    yield ff
            else:
                yield f

    regexes["filename"] = extract_filenames

    primitives["http"]  = r"h?_?[tx]_?[tx]_?[px]_?"
    primitives["https"] = r"h?_?[tx]_?[tx]_?[px]_?s_?"
    primitives["ftp"]   = r"f(?:t|x)p"
    primitives["ftps"]  = r"f(?:t|x)ps"
    primitives["sftp"]  = r"sf(?:t|x)p"

    primitives["protocol"] = r"""
        (?:
           file
         | gopher
         | news
         | nntp
         | telnet
         | h?_?[tx]_?[tx]_?[px]_?(?:s_?)?
         | f(?:t|x)ps?
         | sf(?:t|x)p
         | rwhois
        )
    """

    # many urls are defanged by ommitting the colon and possibly one slash
    primitives["proto_sep"] = r"%(colon)s?//?" % primitives

    primitives["port"] = r"""
        (?:
           6553[0-5]
         | 655[0-2][0-9]
         | 65[0-4][0-9]{2}
         | 6[0-4][0-9]{3}
         | [1-5][0-9]{4}
         | [1-9][0-9]{3}
         | [1-9][0-9]{2}
         | [1-9][0-9]
         | [1-9]
        )
    """

    # Standard Uniform Resource Locators (URLs)
    # note: since protocol is optional this will actually match
    # plain FQDN and ip addresses as well as CIDR and host/nnnn...that
    # gets filtered later.
    # note: "%%" due to format with primitives
    _url_pat = re.compile(r"""
        \b(
         (?: %(protocol)s %(proto_sep)s )?
         (?: [a-z0-9](?: [a-z0-9\._%%+\-]+ )? %(at)s )?  # maybe username
         (?: %(fqdn)s | %(ipv4)s )
         (?: %(colon)s %(port)s )?
         (?:
            (?: / | \?)
            # paths can be defanged
            (?: %(dot)s | [\w?\\+&%%\$#\=~_\-:/\.,;] )+
                          [\w?\\+&%%\$#\=~_\-:/]
           | /  # maybe just a slash
         )?
         # not followed by (using \b misses trailing slashes)
         (?! [\w?\\+&%%\$#\=~_\-:/] )
        )
    """ % primitives, re.I|re.X)

    # filters ipv4/port and CIDR
    _ip_slash_port_pat = re.compile(r"^%(ipv4)s/\d+$" % primitives, re.I|re.X)
    # filters CIDR followed by ASN with no space
    _cidr_asn_pat = re.compile(r"%(ipv4cidr)s%(asn)s" % primitives, re.X)
    _ipv4_list_pat = re.compile(r"%(ipv4)s/%(ipv4)s" % primitives, re.X)
    _dot_pat = re.compile(primitives["dot"], re.I|re.X)
    _colon_pat = re.compile(primitives["colon"], re.I|re.X)

    def extract_urls(text):
        urls = _url_pat.findall(text)
        while urls:
            url = urls.pop(0)
            if '/' not in url or _ip_slash_port_pat.search(url):
                # note that this also skips bare IP or FQDN
                continue
            if url.endswith('/') and len(url.split('/')) == 2:
                continue
            if _cidr_asn_pat.search(url):
                continue
            if _ipv4_list_pat.search(url):
                continue
            yield url
            # malformed URLs can make urlparse barf
            url = _dot_pat.sub('.', url)
            url = _colon_pat.sub(':', url)
            (_, _, _, _, query, _) = urllib.parse.urlparse(url)
            query = re.sub("&amp;", "&", query)
            for k, v in urllib.parse.parse_qsl(query):
                urls.extend(_url_pat.findall(v))

    regexes["url"] = extract_urls

    # MD5 Hash Value
    regexes["md5"] = re.compile(r"\b (?:0x)? ( [0-9a-f]{32} ) \b", re.I|re.X)

    # SHA1 hash value
    regexes["sha1"] = re.compile(r"\b (?:0x)? ( [0-9a-f]{40} ) \b", re.I|re.X)

    # SHA256 hash value
    regexes["sha256"] = re.compile(r"\b (?:0x)? ( [0-9a-f]{64} ) \b", re.I|re.X)

    # SSDeep hash value
    regexes["ssdeep"] = re.compile(r"""
        \b
        ( [1-9][0-9]{0,7} : [a-z0-9\/\+]{5,} : [a-z0-9\/\+]{5,} )
        \b
    """, re.I|re.X)

    # HKCU, HKLM, HKU, HKCC, CLSID, IID, TypeLib, Interface, REGISTRY
    # HKEY_LOCAL_MACHINE, HKEY_USERS, HKEY_CURRENT_USER, HKEY_CURRENT_CONFIG
    primitives["rkey"] = r"""
        (?:CLSID|(?:HK(?:EY\_(?:CURRENT\_(?:CONFIG|USER)|LOCAL\_MACHINE|USERS)|C(?:C|U)|LM|U))|(?:I(?:nterface|ID))|REGISTRY|TypeLib)
    """

    # Standard file path syntax
    _filepath_pat = re.compile(r"""
        # preceded by non-word character eliminates registry keys
        \W
        (
          # mount point
          (?: (?: [a-z]:\\ ) | (?: \\ ) | (?: %%[a-z]+%%\\ ) )
          (?:
            (?:
             # things followed by backslash
             # note: explicitely exclude \n, re.MULTILINE doesn't work for this?
             (?: [\w\[{][^/\\:*?"<>|:;=,\n]* (?<!\s) \\ )+
             (?: (?: %(filename_promisc_ng)s\b ) | [\w\[{][^/\\:*?"<>|:;=,\n\s]* )?
            )
            # or just a single path component
            | (?: (?: %(filename_promisc_ng)s\b ) | [\w\[{][^/\\:*?"<>|:;=,\n\s]* )
          )
        )
    """ % primitives, re.I|re.X)

    def extract_filepaths(text):
        for path in _filepath_pat.findall(text):
            # skip registry keys
            if re.search(r"^\\?%(rkey)s\\" % primitives, path, re.X):
                continue
            # many times registry keys follow a path on the same line
            path = re.sub(r"\s+\\?%(rkey)s\\.*" % primitives, "", path, re.X)
            # anything after multiple spaces is typically garbage
            path = re.sub(r"\s{2,}.*", "", path)
            # get rid of trailing characters than aren't word chars or brackets
            path = re.sub(r"[^\w}]+$", "", path)
            # skip stubby paths and overly greedy paths
            if len(re.sub(r"^[a-z]:", "", path, re.I)) < 5:
                continue
            if len(path) > 200:
                continue
            if "..." in path or "\\r\\n" in path:
                continue
            # filter out octet streams
            if re.search(r"^[^\\]*?\\\d{3}[a-z]?\\", path, re.I):
                continue
            # drop charset encodings
            if path.startswith("\\x"):
                continue
            if "___" in path:
                continue
            if "&quot" in path:
                if re.search(r"^([a-z]:|%)", path, re.I):
                    path = re.sub(r"&quot;?", "", path)
                else:
                    continue
            yield path

    regexes["filepath"] = extract_filepaths

    # Registry key path
    regexes["regkey"] = re.compile(r"""
        \b(
          %(rkey)s \\
          (?: [\w\-\^%%#@!\(\)+{}\[\]_~=]+ \\ )+
              [\w\-\^%%#@!\(\)+{}\[\]_~=]*
        )\b
    """ % primitives, re.I|re.X)

    # User agent strings
    _ua_pat = re.compile(r"""
        user-agent: \s+
        (
         [a-z0-9_;:+&,@#!$%^*=\s\(\){}[\]\./\\-]+
         [a-z0-9_;:+&,@#!$%^*=\(\){}[\]/\\-] # don't end in space or .
        )
    """, re.I|re.X)

    # used for filtering out HTTP headers on same line
    _ua_split_pat = re.compile(r"\s*[a-z\-]+:\s+", re.I)

    def extract_useragent(text):
        for ua in _ua_pat.findall(text):
            fields = _ua_split_pat.split(ua)
            if fields[0]:
                yield fields[0]

    regexes["useragent"] = extract_useragent

    # CVEs
    regexes["cve"] = re.compile(r"""
        \b(
         CVE
         (?:\s+|[\W_])?  # space, dash, comma, and...?
         \d{4}
         (?:\s+|[\W_])?
         \d+
        )\b
    """, re.I|re.X)

    # country names and adjectivals
    # cc regex build by bin/build_cc_re
    primitives["cc"] = re_auto.cc
    _cc_pat = re.compile(r"\b(%(cc)s)\b" % primitives, re.X)

    def extract_cc(text):
        for cc in _cc_pat.findall(text):
            # zap newlines, excessive whitespace
            cc = re.sub(r"\s+", " ", cc)
            yield cc, re_auto.cc_lookup[cc.lower()]

    regexes["cc"] = extract_cc

    # Internet Service Provider
    _isp_pat = re.compile(r"""
        ^\W*
        ISP
        # not immediately followed by these words
        (?! \s+ (?: as | in | on | has | is | for) \b)
        # also not eventually followed by any of these words
        (?!
          .*?\s+
          (?:
              [Nn][Oo][Tt][Ii][Ff]          # notify/notified/notification
            | [Cc][Oo][Nn][Tt][Aa][Cc][Tt]  # contact/contacted
            | [Dd][Aa][Tt][Ee]
            | [Mm][Ii][Tt][Ii][Gg][Aa][Tt]
            | [Pp][Rr][Oo][Vv][Ii][Dd][Ee][Rr]
            | [Ii][Nn][Cc][Ii][Dd][Ee][Nn][Tt]
            | [Uu][Nn][Kn][Oo][Ww][Nn]
          )
          .*?$  # don't search past newlines
        )
        # possibly followed by other words (20 char or less)
        # and a colon/dash/eq (don't breach newline)
        (?:\s*[^\-:=\n]{,20}[\-:=])?
        # mandatory whitespace
        \s+
        # capture the rest of the string if it's between 3 and 50 chars
        (.{3,50}?)
        \s*
        $ # and finally a newline
    """, re.X|re.MULTILINE)

    def extract_isp(text):
        for isp in _isp_pat.findall(text):
            isp = re.sub(r"&amp;", "&", isp)
            if re.search(r"Unknown", isp, re.I):
                continue
            yield isp

    regexes["isp"] = extract_isp

    _asn_owner_pat = re.compile(r"""
        ASN\s+Owner\s*[:\-]?\s*(.*?)\s*$
    """, re.MULTILINE|re.I|re.X)

    def extract_asn_owner(text):
        for owner in _asn_owner_pat.findall(text):
            if re.search(r"Unknown", owner, re.I):
                continue
            yield owner

    regexes["asnown"] = extract_asn_owner

    # based on code from @author: adh
    regexes["incident"] = re.compile(r"""
        \b(
          vu\s*\#\s*\d+        # certcc
        | cert\s*\#\s*\d+      # certcc
        | info\s*\#\s*\d+      # certcc
        | ar\s*\#\s*d+         # certcc
        | fedcirc\s*\#\s*\d+   # certcc
        | jpcert\s*\#\s*\d+    # jpcert
        | ficora\s*\#\s*\d+    # cert-fi
        | jvn\s*\#\s*\d+       # jpcert
        | jvnvu\s*\#\s*\d+     # jpcert
        | auscert\s*\#\s*\w+   # auscert
        | ics\s*-?\s*vu\s*-?\s*#\s*\d+    # ics-cert
        | ics\s*-?\s*info\s*-?\s*#\s*\d+  # ics-cert
        | vr\s*-\s*\d+        # certcc
        | info\s*-\s*\d+      # certcc
        | vcr\s*-\s*\d+       # certcc
        | taq\s*-\s*\d+       # certcc
        | gir\s*-\s*\d+       # certcc
        | vcall\s*-\s*\d+     # certcc
        #| cve-\d+-\d+         # cve
        | cwe-\d+             # cwe
        | apple-sa-\d+-\d+-\d+-\d+  # apple
        | ms\d+-\d+           # microsoft
        | kb\d{4,}            # microsoft
        | usn-\d+-\d+         # ubuntu
        | inc\d{4,}           # us-cert incidents
        | vrf\s*\#\s*[A-Z0-9-]+  # certcc
        | vend\s*\#\s*\d+     # certcc
        | MSRC\s+Case\s+\d+   # MSRC
        | QPSIIR-\d+          # qualcomm
        | TRK:{4,}            # MSRC
        | TALOS-CAN-\d+       # Cisco Talos
        | Ticket\s+No.\s+\d+  # Fortinet
        | Ticket\s*\#\s*\d+   # multiple orgs
        | TippingPoint\s+Service\s+Request\s+Case\s+#\s*\d+  # tippingpoint
        | Case\s+\#\s*\d+     # multiple orgs
        | CERTIn-\d+          # cert-in
        | Bug\s*\d+           # multiple orgs
        | sr\s*\#\s*\d+-\d+   # ?? us-cert
        | br\s*\#\s*\d+       # CTIR Gov
        | mar-\d{8}-[A-Z]     # MAR (Malware Analysis Report)
        | soc-\d{8}-\d+       # SOC tracking number
        | \d{4}-\d{4}-\d{3}   # CSIRT/NRC
    
        # older stuff
    
        | abuse\s*\#\d+       # ??
        | alert\s*\#\s*probe  # certcc
        | apacs\s*\#\s*\d+    # ??
        | ciac\s*\#\s*\d+     # ciac
        | citsirt\s*\#\s*\d+  # CITSIRT
        | incident\s*\#\s*(?!INC)\w+  # multiple orgs
        | ipa\s*\#\s*\w+      # ??
        #| item\s*\#\s*\d      # ??
        | kr\s*\#\s*\d+       # ??
        | marco\s*\#\s*\d+    # ??
        | niscc\s*\#\s*\d+    # niscc
        | ncsc-nl\s*\#\s*\d+  # ncsc
        | ouspg\s*\#\s*\w+    # ouspg
        | afcert\s*\#\s*\d+   # afcert
        | assist\s*\#\s*\w+   # ??
        | dfncert\s*\#\s*\d+  # dfncert
        | dfn\s*\#\s*\d+      # dfncert
        | escert\s*\#\s*\d+   # escert?
        | eurocert\s*\#\s*\w+ # eurocert?
        | dkcert\s*\#\s*\d+   # dkcert
        | funet\s*\#\s*\d+    # funet
        | janet\s*\#\s*\d+    # janet
        | mxcert\s*\#\s*\d+   # mxcert
        | nasa\s*\#\s*\d+     # nasa
        | nasirc\s*\#\s*\d+   # nasirc
        | navcirt\s*\#\s*\w+  # navcirt
        | nearnet\s*\#\s*\d+  # nearnet
        )\b
    """, re.I|re.X)

    primitives["malware"] = re_auto.malware

    _malware_pat = re.compile(r"""
        \b( (?: (?: [\w/\-\.!:]+? [/\-\.!:] )?
                    %(malware)s
                    [/\-\.!:] [\w/\-\.!:]+
            )
          |
            (?:     [\w/\-\.!:]+? [/\-\.!:]
                    %(malware)s
                (?: [/\-\.!:] [\w/\-\.!:] )?
            )
        )\b
    """ % primitives, re.X)

    _k7_malware_pat = re.compile(r"""
        ( [a-z\-]+ \s+ \( \s+ [0-9a-f]{9} \s+ \) )
    """, re.I|re.X)

    def extract_malware(text):
        for mal in _malware_pat.findall(text):
            mal = re.sub(r"[/\-\.!:]{2,}.*$", "", mal)
            mal = re.sub(r"[\-\.!/]$", "", mal)
            mal = re.sub(r"^[\-\.!/]", "", mal)
            if not re.search(r"[\-\.!/]", mal):
                continue
            if len(mal) >= 50:
                continue
            if len(mal) < 8:
                continue
            if len(mal.split('/')) > 3 or len(mal.split('-')) > 3:
                continue
            # filter out email Message-IDs
            if re.search(r"\b[A-F0-9]{12}\b", mal) and '!' not in mal:
                continue
            # filter out Virus-Submit
            if "Submit" in mal:
                continue
            # research URL fragments
            if re.search(r"\.(html|aspx)$", mal):
                continue
            # filter out w3.org artifacts
            if re.search(r"\.(com|org|gov|mil|edu)", mal):
                continue
            # Mal or Virus with a dash are usually false positives
            if re.search(r"(Mal-|-(Mal|Virus))", mal):
                continue
            # avoid filenames referencing malware
            if _ends_with_file_ext_pat.search(mal):
                continue
            mal = re.sub(r"^name:", "", mal)
            yield mal
        for mal in _k7_malware_pat.findall(text):
            yield mal

    regexes["malware"] = extract_malware

    _topic_pat = re.compile(r"\b(%s)\b" % re_auto.topic, re.I|re.X)

    def extract_topic(text):
        for m in _topic_pat.finditer(text):
            topic = m.group(1)
            normalized = None
            if re.search(r"fraud", topic, re.I):
                lo, hi = m.span()
                lo = max(lo - 10, 0)
                if re.search(r"anti", text[lo:hi], re.I):
                    continue
                normalized = "fraud"
            elif re.search(r"exfiltrat", topic, re.I):
                lo, hi = m.span()
                lo = max(lo - 30, 0)
                if re.search(r"\b(not?|can('t|not))\b", text[lo:hi], re.I):
                    continue
                normalized = "exfiltration"
            elif re.search(r"^dos$", topic, re.I):
                if topic == "dos":
                    # ignore if all lower
                    continue
                lo, hi = m.span()
                lo = max(lo - 25, 0)
                hi = hi + 15
                if re.search(r"D/DoS", text[lo:hi], re.I):
                    continue
                if re.search(r"state|use(r|es)", text[lo:hi], re.I):
                    continue
                normalized = "DoS"
            elif re.search(r"spam", topic, re.I):
                lo, hi = m.span()
                lo = max(lo - 1, 0)
                if (text[lo] == '-' and text[hi] == '-') or text[lo] == '=':
                    # anti spam mail headers and metadata
                    continue
                lo, hi = m.span()
                lo = max(lo - 20, 0)
                hi = hi + 20
                if re.search(r"@", text[lo:hi]):
                    # spam reporting in email addresses
                    continue
                lo, hi = m.span()
                lo = max(lo - 10, 0)
                if re.search(r"anti", text[lo:hi], re.I):
                    continue
                normalized = "spam"
            elif re.search(r"spy\b", topic, re.I):
                lo, hi = m.span()
                lo = max(lo - 10, 0)
                hi = hi + 10
                if re_auto.by_topic["spyware"].search(topic):
                    if re.search(r"(^spy|\sspy)\b", topic, re.I):
                        normalized = "spying"
                    else:
                        normalized = "spyware"
                else:
                    normalized = "spying"
            elif re.search(r"sniff", topic, re.I):
                lo, hi = m.span()
                lo = max(lo - 10, 0)
                hi = hi + 10
                if re.search(r"log|web", text[lo:hi], re.I):
                    continue
                normalized = "sniffing"
            elif re.search(r"crack", topic, re.I):
                lo, hi = m.span()
                lo = max(lo - 15, 0)
                hi = hi + 15
                if re.search(r"screen|down", text[lo:hi], re.I):
                    continue
                normalized = "cracking"
            elif re.search(r"identity", topic, re.I):
                lo, hi = m.span()
                hi = hi + 10
                if re.search(r"occurs", text[lo:hi], re.I):
                    continue
                normalized = "identity theft"
            elif re.search(r"compromis", topic, re.I):
                lo, hi = m.span()
                lo = max(lo - 35, 0)
                if re.search(r"check", text[lo:hi], re.I):
                    continue
                normalized = "compromise"
            elif re.search(r"reflection", topic, re.I):
                lo, hi = m.span()
                hi = hi + 20
                if not re.search(r"attack|traffic|flood", text[lo:hi], re.I):
                    lo = max(lo - 20, 0)
                    if not re.search(r"""
                        \b
                        DNS|NTP|TCP|UDP|ICMP|SSDP|D?DoS|service
                        \b
                    """, text[lo:hi], re.I|re.X):
                        continue
                lo, hi = m.span()
                if lo > 0 and not re.search(r"\s", text[lo-1]):
                    continue
            lo, hi = m.span()
            lo = max(lo - 20, 0)
            if re.search(r"\b(not?|isn't|can('t|not))\b", text[lo:hi], re.I):
                continue
            lo, hi = m.span()
            hi = hi + 10
            if re.search(r"\bno\b", text[lo:hi], re.I):
                continue
            lo, hi = m.span()
            lo = max(lo - 30, 0)
            if re.search(r"\bin\s+case\b", text[lo:hi], re.I):
                continue
            lo, hi = m.span()
            lo = max(lo - 240, 0)
            hi = hi + 240
            if re.search(r"\b(what\s+(is|are))|where\s+can|schemes?|detector\b",
                         text[lo:hi], re.I):
                continue
            yield topic, normalized

    regexes["topic"] = extract_topic

    return primitives, regexes
