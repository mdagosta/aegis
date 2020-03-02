#-*- coding: utf-8 -*-

# Overall system environment config


# Python Imports
import logging

# Extern Imports
import tornado.options
from tornado.options import options

# Project Imports
import aegis.stdlib

def get(config_name):
    config_name = tornado.options.options._normalize_name(config_name)
    config_val = options._options.get(config_name)
    if config_val:
        return config_val.value()

def aegis_dir():
    return aegis.stdlib.absdir(__file__)
