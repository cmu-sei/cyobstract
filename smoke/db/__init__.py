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

import os, sys, sqlite3

import smoke
from smoke import ConfigError

config = smoke.config()

_drivers = {}
_drivers_init_done = False

def _drivers_init():
    global _drivers_init_done
    for p in os.listdir(os.path.dirname(os.path.realpath(__file__))):
        if p.startswith("db_driver") and p.endswith(".py"):
           __import__("smoke.db." + p[:-3], globals())
        _drivers_init_done = True

_default_driver = None

def register_driver(driver, mod):
    """
    Registers a smoke database driver object with the this
    module.  Driver modules generally register themselves,
    and this function is only of interest to driver writers.
    """
    global _default_driver
    if driver in _drivers:
        raise ConfigError("DB driver %s is already registered." % driver)
    if not _default_driver:
        _default_driver = driver
    _drivers[driver] = mod

def unregister_driver(driver):
    _drivers.pop(driver)

def get_drivers():
    """
    Returns a list of registered drivers.
    """
    if not _drivers_init_done:
        _drivers_init()
    return tuple(_drivers.keys())

_driver = None
def driver():
    global _driver
    if not _drivers_init_done:
        _drivers_init()
    if not _driver:
        driver = config.db_driver or _default_driver
    return _drivers[driver]

###

# The following functions need to be present in a db driver module

def fetch_iids():
    """
    Return all incident IDs

    arguments: none
    returns: iterator of incident IDs
    """
    return driver().fetch_iids()

def fetch_iids_with_org():
    """
    Return all incident IDs along with their organization of origin

    arguments: none
    returns: iterator of tuples (incident_id, organization)
    note: if there is no organization, use None
    """
    return driver().fetch_iids_with_org()

def fetch_iid_org(iid):
    """
    Return the organization of origin for the given incident ID

    arguments: incident_id
    returns: organization name
    """
    return driver().fetch_iid_org(iid)

def iid_count():
    """
    Return the total nuber of incident reports

    arguments: none
    returns: iid_count
    """
    return driver().iid_count()

def fetch_bulk_text():
    """
    Return all incident reports as efficiently as possible

    aruments: none
    returns: iterator of tuples (incident_id, text)
    """
    return driver().fetch_bulk_text()

def bulk_text_count():
    """
    Return the total count of bulk incident reports (it could be
    different due to worklogs, etc)

    arguments: none
    returns: bulk_text_count
    """
    return driver().bulk_text_count()

def fetch_incident_report(iid):
    """
    Return a particular incident report

    arguments: incident_id
    returns: incident text
    """
    return driver().fetch_incident_report(iid)

def fetch_entry(iid):
    """
    OPTIONAL

    Fetch a particular incident report (if it's different than
    the result from fetch_incident_report()). For example, in
    some implementations fetch_incident_report() will append
    the worklogs to the initial report. This just returns the
    report.
    """
    return driver().fetch_entry(iid)

###
