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

'''
Regex-based observable extractor, borrowed from S. Perl
'''
from future import standard_library
standard_library.install_aliases()
from builtins import next
from builtins import str
from builtins import object

from multiprocessing import Pool
import pandas as pd
import pdb
from progress.bar import Bar
import re, urllib.request, urllib.error, urllib.parse, urllib.parse

from . import regex, re_auto

primitives, regexes = regex.create_master_regexes_dict()

url_proto_pat = re.compile(r"""
    ^ %(protocol)s %(proto_sep)s
    """ % primitives, re.I|re.X)

html_entity_pat = re.compile(r"(%s)" % re_auto.entities, re.I|re.X)

def decode_entities(text):
    def subst(match):
        return re_auto.entity_map.get(match.group(1))
    return html_entity_pat.sub(subst, text)

def clean_observable(observable, rtype):
    ''' Transform an observable into a more clean, standardized form 
    
    Args:
        observable (str): the string to clean.
        rtype (str): the type of observable (email, IP, etc.) 
    '''
    try:
        observable, normalized = observable
        if normalized:
            return normalized
    except ValueError:
        pass
    observable = observable.strip()
    observable = re.sub(r"%(dot)s"   % primitives, ".", observable, flags=re.X)
    observable = re.sub(r"%(at)s"    % primitives, "@", observable, flags=re.X)
    observable = re.sub(r"%(colon)s" % primitives, ":", observable, flags=re.X)
    # lowercase non url & filepath matches
    if not rtype == "url" and not rtype == "filepath" \
        and not rtype == "filename" and not rtype == "cc" \
        and not rtype == "asn" and not rtype == "cve":
        observable = observable.lower()                        

    # trim user agent-strings
    if rtype=="useragent":
        # check for references to 'host:' and/or 'accept:'
        _hstndx = -1
        try:
            _hstndx = observable.index("host:")
            # check for 'accept' 
            _acptndx = observable.index("accept:")
            if _acptndx >= 0 and _hstndx >= 0 and _acptndx < _hstndx:
                _hstndx = _acptndx
        except:
            pass
        if _hstndx >= 0:
            observable = observable[:_hstndx].strip()
    elif rtype == "url":
        observable = re.sub(r"^%(http)s%(proto_sep)s" % primitives,
                            "http://", observable, flags=re.I|re.X)
        observable = re.sub(r"^%(https)s%(proto_sep)s" % primitives,
                            "https://", observable, flags=re.I|re.X)
        observable = re.sub(r"^%(ftp)s%(proto_sep)s" % primitives,
                            "ftp://", observable, flags=re.I|re.X)
        observable = re.sub(r"^%(ftps)s%(proto_sep)s" % primitives,
                            "ftps://", observable, flags=re.I|re.X)
        observable = re.sub(r"^%(sftp)s%(proto_sep)s" % primitives,
                            "sftp://", observable, flags=re.I|re.X)
        if not url_proto_pat.search(observable):
            observable = "http://" + observable
    elif rtype == "cve":
        m = re.search(r"(\d+)-(\d+)", observable)
        observable = "CVE-%s-%s" % (m.group(1), m.group(2))
    elif rtype == "asn":
        m = re.search(r"(\d+(?:\.\d+)?)", observable)
        observable = m.group(1)
        if '.' in observable:
            hi, lo = observable.split('.')
            observable = str((65536 * int(hi)) + int(lo))
        observable = "AS" + observable
    elif rtype == "ipv4range" or rtype == "ipv6range":
        observable = re.sub("\s*-\s*", "-", observable)
    elif rtype == "isp" or rtype == "asnown":
        observable = observable.upper()
    elif rtype == "incident":
        observable = re.sub("\s*#\s*", " #", observable)
        if re.search("^INC\d+$", observable, re.I):
            m = re.search("(\d+)", observable)
            digits = m.group(0)
            observable = "INC" + "0" * (12 - len(digits)) + digits
        elif re.match(r"\d{4}-\d{4}-\d{3}", observable):
            observable = "CSIRT/NRC %s" % observable
        if re.match(r"(ticket|incident|bug|case)", observable, re.I):
            observable = observable.capitalize()
        else:
            observable = observable.upper()
    elif rtype == "cc":
        observable = re.sub(r"\s+", " ", observable)
        observable = re_auto.cc_map[observable.lower()]
    elif rtype == "topic":
        for topic, pat in re_auto.per_topic:
            if pat.search(observable):
                observable = topic
                break
    return observable

def extract_observables(text):
    """
    For each observable type, use the corresponding regex or
    callable to extract observables (such as IP addresses)
    from the given text and return their normalized forms.
    """
    results = {}
    if not text:
        return results
    try:
        text = text.read()
    except AttributeError:
        pass
    text = decode_entities(text)
    for typ, regex in regexes.items():
        if callable(regex):
            matches = regex(text)
        else:
            matches = regex.findall(text)
        observables = set()
        for match in matches:
            normalized = None
            try:
                observable, normalized = match
            except ValueError:
                observable = match
            if not observable:
                continue
            if not normalized:
                normalized = clean_observable(observable, typ)
            observables.add(normalized)
        results[typ] = tuple(sorted(observables))
    return results

class _extract_observables_worker(object):
    def __init__(self, id_column, text_column):
        self.id_column = id_column
        self.text_column = text_column
 
    def __call__(self, row):
        out_list = []
        text = row[1][self.text_column]
        for key, values in extract_observables(text).items():
            for value in values:
                out_list.append([row[1][self.id_column], key, value]) 
        return out_list

def apply_extract_observables(df, id_column, text_column, n_cores = None, chunksize = 10):
    ''' Applies the extract_observables function to each row of a pandas dataframe
    
    Args:
        df (pandas DataFrame): Must contain an id column and a text column
        id_column (str): column of df that has a unique identifier for each row
        text_column (str): column of df that has the text from which to extract observables
        n_cores (int): specify the number of cores to use; defaults to all the cores
        chunksize (int): number of rows of the text_column should be processed per
            multiprocess.Pool().map iteration -- relevant only if n_cores != 1.
    
    Returns: A pandas dataframe 
    '''
    if not n_cores:
        pool = Pool() #automatically uses all available cores
    else:
        pool = Pool(processes = n_cores)    
    bar = Bar('Processing', max=df.shape[0])
    observables_list = []
    FUN = _extract_observables_worker(id_column, text_column)
    for _, obs in enumerate(pool.imap_unordered(FUN, df.iterrows(), chunksize)):
        for item in obs:
             observables_list.append(item)
        bar.next()
    bar.finish()
    pool.close()
    pool.join()
    return pd.DataFrame(observables_list, columns=[
        id_column, 'observable_type', 'observable_value'])

def extract(text, regex_name):
    '''
    Returns a list of regex matches from a body of text
    :param text: (string) to extract regex matches from
    :param regex_name: (string) a key of the extract.regexes dict
    :return: list of strings
    '''
    if regex_name not in list(regexes.keys()):
        raise Exception("regex_name " + regex_name +
                        " is not valid. Run `extract.regexes.keys()` to see your options")
    regex = regexes[regex_name]
    if callable(regex):
        return regex(text)
    else:
        return regex.findall(text)
