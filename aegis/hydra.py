#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Hydra - The water monster of legend with multiple serpent heads on one body. This is the batch and worker system for downtime/background processing.
#         Main Thread is the "batch" checking what should run, worker threads operate the work queue.

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
import aegis.stdlib
import aegis.model

import bday
bday_path = bday.__path__[0]
sys.path.insert(0, bday_path)

#aegis.stdlib.logw(sys.path, "SYS.PATH")
import bday.config
bday.config.initialize()

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
        self.logw = aegis.stdlib.logw
        self.thread_name = threadname or 'Hydra-%02d' % options.hydra_id
        HydraThread.__init__(self, name=self.thread_name)


    # Must be a clever way to use the claim mechanism. Maybe SIGHUP resets claims?
    def is_lead_process(self):
        if options.batch_id != 0:
            return False
        if self.tmpl['env'] != 'prod':
            return True
        if self.tmpl['env'] == 'prod' and socket.gethostname() in ('bday01', 'bday01.zuno.com'):
            return True


    def process(self):
        global quitting
        logging.info("%s running background processing", self.name)
        try:
            #if self.is_lead_process():
            #    log.info("Lead Process %s clearing claimed/stuck items for retry...", self.name)
            #    # Fetch all class names
            #    for batch_task in model.BatchTask.get_all():
            #        model.BatchTask.reset(batch_task['class_name'])
            #        model.BatchTask.schedule_next(batch_task['class_name'], batch_task['next_run_tx'])

            while(not quitting):
                self.iter_cnt += 1
                try:
                    # Batch Loop: scan hydra_type for runnable batches
                    for hydra_type in aegis.model.HydraType.scan():
                        if quitting: break
                        # Check if the task is runnable
                        runnable = aegis.model.HydraType.get_runnable(hydra_type['hydra_type_id'])
                        if runnable:

                            # Put a hydra_queue
                            # Reset


                            #hydra_queue = aegis.model.HydraQueue.scan_work_type_unfinished(hydra_type['hydra_type_id'])
                            #if hydra_queue:
                            #    log.warning("HydraQueue item %s already exists. Skipping...", hydra_type['hydra_type_name'])
                            #    continue
                            ## Modify start to return a value to do the 'claim' mechanism
                            #started = model.BatchTask.start(batch_task['class_name'])
                            #if not started:
                            #    log.warning("Got a runnable task %s that was already started. Skipping...", batch_task['class_name'])
                            #    continue
                            #log.info('Put work_queue item for %s', batch_task['class_name'])
                            #model.WorkQueue.insert(work_type['work_type_id'], datetime.datetime.utcnow(), work_type['priority_ind'])

                            hydra_type.schedule_next()
                            _hydra_type = aegis.model.HydraType.get_id(hydra_type['hydra_type_id'])
                            aegis.stdlib.logline("Run Hydra Type: %s   Next Run: %s" % (_hydra_type['hydra_type_name'], _hydra_type['next_run_dttm']))

                            #hydra_queue = {}
                            #hydra_queue['hydra_type_id'] = hydra_type['hydra_type_id']
                            #hydra_queue['priority_ndx'] = hydra_type['priority_ndx']

                            #'work_data',
                            #'start_dttm',



                except Exception as ex:
                    logging.exception("Batch had an inner loop failure.")
                # Iterate!
                #aegis.stdlib.logline("The Hydra Sleeps")
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
            time.sleep(options.sleep)   # Main thread doesn't do much, sleep is interrupted by signal


if __name__ == "__main__":
    #tornado.options.parse_command_line()
    global daemon
    daemon = Hydra()
    daemon.start()
    thread_wait(daemon)
    sys.exit(0)
