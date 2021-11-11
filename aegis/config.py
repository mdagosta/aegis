#-*- coding: utf-8 -*-

# Overall system environment config


# Python Imports
import logging
import os
import syslog

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


class SyslogHandler(logging.Handler):
    facility_map = {'local1': syslog.LOG_LOCAL1, 'local3': syslog.LOG_LOCAL3, 'local4': syslog.LOG_LOCAL4, 'local5': syslog.LOG_LOCAL5, 'local6': syslog.LOG_LOCAL6}
    priority_map = {'DEBUG': syslog.LOG_DEBUG, 'INFO': syslog.LOG_INFO, 'WARNING': syslog.LOG_WARNING, 'ERROR': syslog.LOG_ERR, 'CRITICAL': syslog.LOG_CRIT}
    root_logger = None

    def __init__(self, ident, facility, *args, **kwargs):
        super(SyslogHandler, self).__init__(*args, **kwargs)
        self.ident = ident
        self.facility = SyslogHandler.facility_map[facility]

    def emit(self, record):
        msg = self.format(record)
        priority = self.priority_map[record.levelname]
        syslog.openlog(self.ident, syslog.LOG_PID, self.facility)
        syslog.syslog(priority, msg)
        syslog.closelog()

    @classmethod
    def setup_syslog(cls):
        if not cls.root_logger and options.syslog_ident and options.syslog_address:
            syslog_level = cls.priority_map[options.syslog_level.upper()]
            console_level = cls.priority_map[options.console_level.upper()]
            # Root Logger
            cls.root_logger = logging.getLogger()
            cls.root_logger.setLevel(min(syslog_level, console_level))
            # Initial Stream Handler
            stream_handler = cls.root_logger.handlers[0]
            stream_handler.setLevel(console_level)
            # Setup Syslog Handler
            syslog_handler = SyslogHandler(options.syslog_ident, options.facility)
            syslog_handler.level = syslog_level
            syslog_handler.setFormatter(logging.Formatter("%(threadName)s:%(module)s.py:%(lineno)d | %(message)s"))
            cls.root_logger.addHandler(syslog_handler)
