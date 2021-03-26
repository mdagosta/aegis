#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Aegis is your shield to protect you on the Brave New Web

# Python Imports
import base64
import datetime
import decimal
import hmac
import hashlib
import json
import logging
import operator
import os
import requests
import requests.auth
import stat
import sys
import time

# Extern Imports
from tornado.options import options
import aegis.hydra
import aegis.stdlib

# Project Imports
import config
import model


class Snowballin(object):
    def __init__(self):
        logging.info("SNOWBALLIN")


class SnowballinHydra(aegis.hydra.Hydra):
    def __init__(self):
        aegis.hydra.Hydra.__init__(self)
        self.hydra_head_cls = Snowball
        self.num_heads = 3


class Snowball(aegis.hydra.HydraHead):

    def exception_alert(self, ex):
        # Alert and debug hooks
        #mail.error_email(None)
        logging.error(ex)
        logging.error("IMPLEMENT ERRORS MODE")

    def housekeeping(self, hydra_queue, hydra_type):
        logging.warning("Sweeping up")
        return True, 0


if __name__ == "__main__":
    config.initialize()
    logging.info("Running snowballin.py   Env: %s   Hostname: %s   Database: %s/%s", options.env, options.hostname, options.pg_database, options.pg_hostname)
    daemon = SnowballinHydra()
    daemon.start()
    daemon.main_thread()
    sys.exit(0)
