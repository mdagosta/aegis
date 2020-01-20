#-*- coding: utf-8 -*-

# Overall system environment config


# Python Imports
import logging

# Extern Imports
import tornado.options
from tornado.options import options


def get(config_name):
    config_name = tornado.options.options._normalize_name(config_name)
    config_val = options._options.get(config_name)
    if config_val:
        return config_val.value()
