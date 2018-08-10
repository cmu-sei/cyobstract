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

from past.builtins import basestring

import os, yaml, re

class ConfigError(Exception):
    pass

class Config(object):
    def __init__(self):
        self.repo_path = None
        self.db_uri = None
        self.db_driver = None
        cfg_file = os.path.expanduser("~/.cyobstract")
        if not os.path.exists(cfg_file):
            raise ConfigError("~/.cyobstract not present")
        with open(cfg_file) as f:
            cfg = yaml.load(f)
            self.repo_path = cfg.get('repo_path', None)
            self.db_uri = cfg.get('db_uri', None)
            self.db_driver = cfg.get('db_driver', None)
        if not self.db_uri:
            raise ConfigError("db_uri undefined in ~/.cyobstract")
        if not self.db_driver:
            raise ConfigError("db_driver undefined in ~/.cyobstract")
        self.base_dir = os.path.dirname(
                       os.path.dirname(os.path.realpath(__file__)))
        if not self.repo_path:
            self.repo_path = self.base_dir
        etc_dir = os.path.join(self.repo_path, 'etc')
        # if a custom 'etc' dir exists, use that, otherewise
        # use the stock 'etc' dir
        if os.path.exists(etc_dir):
            self.etc_dir = etc_dir
        else:
            self.etc_dir = os.path.join(base_dir, 'etc')
        self.dat_dir = os.path.join(self.repo_path, 'dat')
        self.tmp_dir = os.path.join(self.repo_path, "tmp")
        self.log_dir = os.path.join(self.repo_path, "log")
        self.iid_dir = os.path.join(self.dat_dir, "iid")
        self.out_dir = os.path.join(self.dat_dir, "out")
        if not os.path.exists(self.dat_dir):
            os.makedirs(self.dat_dir)
        if not os.path.exists(self.iid_dir):
            os.makedirs(self.iid_dir)
        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir)
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        if not os.path.exists(self.tmp_dir):
            os.makedirs(self.tmp_dir)

conf = None
def config():
    global conf
    if not conf:
        conf = Config()
    return conf

def load_and_strip_comments(fh):
    if isinstance(fh, basestring):
        fh = open(fh)
    for line in (x.strip() for x in fh):
        line = re.sub(r"(?:^|\s+)(?<!\\)#.*", "", line)
        line = re.sub(r"\\#", "#", line)
        if line:
            yield line
