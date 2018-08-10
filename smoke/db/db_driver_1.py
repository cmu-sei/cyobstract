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
from smoke import db

config = smoke.config()

conns = {}

def connect():
    pid = os.getpid()
    if not conns.get(pid, None):
        db = config.db_uri
        pid = os.getpid()
        conns[pid] = sqlite3.connect(db, check_same_thread=False)
        tf = lambda x: x.decode(encoding="utf-8", errors="replace")
        conns[pid].text_factory = tf
    return conns[pid]

### The following functions are required by the smoke.db API

def fetch_iids():
    conn = connect()
    c = conn.cursor()
    e = c.execute("SELECT ticket_id FROM tickets")
    for row in e:
        if row[0]:
            yield row[0]

def fetch_iids_with_org():
    conn = connect()
    c = conn.cursor()
    e = c.execute("SELECT ticket_id,ticket_organization FROM tickets")
    for row in e:
        if row[0]:
            yield row[0], row[1] or None

def fetch_iid_org(iid):
    conn = connect()
    c = conn.cursor()
    e = c.execute("""
        SELECT ticket_organization FROM tickets
        WHERE ticket_id = ?
    """, (iid,))
    row = e.fetchone()
    if row and row[0]:
        return row[0]
    else:
        return None

def iid_count():
    conn = connect()
    c = conn.cursor()
    e = c.execute("SELECT COUNT(ticket_id) FROM tickets")
    row = e.fetchone()
    if row and row[0]:
        return row[0]
    else:
        return 0

def fetch_bulk_text():
    conn = connect()
    c = conn.cursor()
    e = c.execute("SELECT ticket_id,ticket_text FROM tickets")
    for row in e:
        yield row[0], row[1]

def bulk_text_count():
    total = 0
    conn = connect()
    c = conn.cursor()
    e = c.execute("SELECT COUNT(*) FROM tickets")
    row = e.fetchone()
    if row and row[0]:
        total += row[0]
    return total

def fetch_incident_report(iid):
    conn = connect()
    c = conn.cursor()
    e = c.execute("SELECT ticket_text FROM tickets WHERE ticket_id = ?", (iid,))
    row = e.fetchone()
    if row and row[0]:
        return row[0]
    else:
        return None

###

db.register_driver('db1', sys.modules[__name__])
