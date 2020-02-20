#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Hydra - the water monster of legend with multiple serpent heads on one body. This is the batch system for downtime processing.

# Python Imports
import datetime
import logging
import os.path
import random
import shutil
import signal
import sys
import threading
import time
import traceback

# Extern Imports
import tornado.options
from tornado.options import define, options
import requests
import slugify

# Project Imports
import stdlib

define('sleep', default=5, type=int)
define('hydra_id', default=0, type=int)


# Graceful shutdown with debug
def debug(sig, frame):
    """Interrupt running process, and provide a python prompt for interactive debugging."""
    id2name = dict([(th.ident, th.name) for th in threading.enumerate()])
    code = []
    for threadId, stack in sys._current_frames().items():
        code.append("\n# Thread: %s(%d)" % (id2name.get(threadId,""), threadId))
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                code.append("  %s" % (line.strip()))
    logging.warning("\n".join(code))

quitting = False
def stop(signal, frm):
    logging.warning('SIGINT or SIGTERM received (%s). Shut down in progress...', signal)
    global quitting, daemon
    quitting = daemon.quit = True
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGUSR1, debug)


class HydraThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)

    def run(self):
        try:
            self.process()
        except Exception as ex:
            logging.exception(ex)
            # XXX TODO chat_hook debug_hook


class Hydra(HydraThread):
    filename = __file__
    thread_name = 'Hydra-%s' % options.hydra_id     # Just a default, commandline options are used below

    def __init__(self, threadname=None):
        # Batch stuff
        self.start_t = time.time()
        self.last_id = 0
        self.processed_cnt = 0
        self.iter_cnt = 0
        self.logw = stdlib.logw
        self.thread_name = threadname or 'Hydra-%02d' % options.hydra_id
        HydraThread.__init__(self, name=self.thread_name)


    def process(self):
        global quitting
        logging.info("%s running background processing", self.name)
        try:
            while(not quitting):
                self.iter_cnt += 1
                try:
                    
                    stdlib.logline("Batch Loop")
                    
                except Exception as ex:
                    logging.exception("Batch had an inner loop failure.")
                # Iterate!
                stdlib.logline("Hydra Sleep")
                time.sleep(options.sleep)

        except Exception as ex:
            logging.exception(ex)
            traceback.print_exc()
            # Alert and debug hooks
        finally:
            self.finish()
            logging.info("%s ending." % self.name)


    def rate_limit(self, key, hostname, delta_sec):
        """ Return True if should be rate-limited """
        attr_name = '%s-%s' % (key, hostname)
        if hasattr(self, attr_name):
            attr = getattr(self, attr_name)
            if attr + datetime.timedelta(seconds=delta_sec) > datetime.datetime.now():
                return True
        setattr(self, attr_name, datetime.datetime.now())
        return False


    def finish(self):
        end_t = time.time()
        exec_t = end_t - self.start_t
        recs_s = max(float(self.processed_cnt), 1.0) / exec_t
        recs_h = max(float(self.processed_cnt), 1.0) / exec_t * 3600
        logging.info("Exec_sec: %4.3f   Records/sec: %4.3f   Records/hr: %4.3f   Iterations: %s", exec_t, recs_s, recs_h, self.iter_cnt)
        logging.info("Records: %d   Last Id: %s   ", self.processed_cnt, self.last_id)


def thread_wait(daemon):
    global quitting
    while threading.active_count() > 1:
        if quitting:
            logging.warning("%s waiting %ss for threads to finish... %s active" % (daemon.filename, options.sleep, threading.active_count()))
            threads = threading.enumerate()
            thr = random.choice(threads[1:])
            if thr != threading.current_thread():
                thr.join(1.0)
        else:
            time.sleep(5)   # Main thread doesn't do much, sleep is interrupted by signal


if __name__ == "__main__":
    tornado.options.parse_command_line()
    global daemon
    daemon = Hydra()
    daemon.start()
    thread_wait(daemon)
    sys.exit(0)
