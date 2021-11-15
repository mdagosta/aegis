#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Hydra - The water monster of legend with multiple serpent heads on one body. This is the batch and worker system for downtime/background processing.
#         Main Thread is just a control. Hydra is the "batch" which checks what should run. HydraHeads are worker threads operating the hydra_queue.

# Python Imports
import datetime
import json
import logging
import random
import os
import signal
import socket
import sys
import threading
import time
import traceback

# Extern Imports
import tornado.options
from tornado.options import define, options

# Project Imports
import aegis.stdlib
import aegis.database
import aegis.model
import aegis.build
import config

define('hydra_id', default=0, type=int)
define('hydra_sleep', default=1, type=int)


class HydraThread(threading.Thread):

    # quitting uses threading.Event() at the class level to synchronize flags between threads
    quitting = threading.Event()
    filename = __file__


    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)
        self.logw = aegis.stdlib.logw
        self.start_t = time.time()
        self.processed_cnt = 0
        self.iter_cnt = 0
        self.last_id = 0


    # Alert and debug hooks likely need to be defined in applications
    def exception_alert(self, ex):
        self.logw(ex, "EXCEPTION ALERT - OVERRIDE ME IN CHILD CLASS")


    def run(self):
        try:
            self.process()
        except Exception as ex:
            logging.exception(ex)
            self.exception_alert(ex)


    def finish(self):
        end_t = time.time()
        exec_t = end_t - self.start_t
        recs_s = max(float(self.processed_cnt), 1.0) / exec_t
        recs_h = max(float(self.processed_cnt), 1.0) / exec_t * 3600
        logging.info("%s ending.  Records: %d   Seconds: %4.3f   Records/sec: %4.3f   Records/hr: %4.3f   Iterations: %s  Last Id: %s", self.name, self.processed_cnt, exec_t, recs_s, recs_h, self.iter_cnt, self.last_id)


    def main_thread(self):
        # Handling signals only works in the main thread
        signal.signal(signal.SIGINT, self.signal_stop)
        signal.signal(signal.SIGTERM, self.signal_stop)
        signal.signal(signal.SIGUSR1, self.signal_debug)
        signal.signal(signal.SIGHUP, self.signal_reset)
        # Main thread is used only as a control thread... monitors quitting variable, and sleep gets interrupted by signal. And that's it!
        while threading.active_count() > 1:
            if HydraThread.quitting.is_set():
                logging.warning("aegis/hydra.py waiting %ss for threads to finish... %s active" % (options.hydra_sleep, threading.active_count()))
                threads = threading.enumerate()
                if len(threads) > 1:
                    thr = random.choice(threads[1:])
                    if thr != threading.current_thread():
                        thr.join(1.0)
            else:
                time.sleep(options.hydra_sleep)


    # Graceful shutdown with debug
    @staticmethod
    def signal_debug(sig, frame):
        """Interrupt running process, and provide a python prompt for interactive debugging."""
        id2name = dict([(th.ident, th.name) for th in threading.enumerate()])
        code = ["Received SIGUSR1 - Dumping Debug Output"]
        for threadId, stack in sys._current_frames().items():
            code.append("\n# Thread: %s(%d)" % (id2name.get(threadId,""), threadId))
            for filename, lineno, name, line in traceback.extract_stack(stack):
                code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
                if line:
                    code.append("  %s" % (line.strip()))
        logging.warning("\n".join(code))


    @staticmethod
    def signal_stop(signal, frm):
        logging.warning('SIGINT or SIGTERM received (%s). Quitting now...', signal)
        HydraThread.quitting.set()


    @staticmethod
    def signal_reset(signal, frm):
        logging.warning("SIGHUP received... clearing stale claims")
        aegis.model.HydraType.clear_claims(minutes=self.stuck_minutes)
        aegis.model.HydraQueue.clear_claims(minutes=self.stuck_minutes)


class HydraHead(HydraThread):

    def __init__(self, hydra_head_id, *args, **kwargs):
        self.hydra_head_id = hydra_head_id
        self.thread_name = 'HydraHead-%02d' % self.hydra_head_id
        self.hostname = socket.gethostname()
        HydraThread.__init__(self, name=self.thread_name)
        self.hydra_type_maxlen = max([len(ht['hydra_type_name']) for ht in aegis.model.HydraType.scan()]+[8])


    def process(self):
        logging.info("Spawning %s", self.name)
        try:
            while(not HydraThread.quitting.is_set()):
                # In the case that the database is down, these fail and the HydraHead will die.
                # The respawning of the head has a 1s sleep to pace out reconnecting to db, and also the new process completely resets aegis.database values.
                if self.hydra_head_id == 0:
                    queue_items = aegis.model.HydraQueue.scan_work_priority(hostname=self.hostname, env=aegis.config.get('env'))
                else:
                    queue_items = aegis.model.HydraQueue.scan_work(hostname=self.hostname, env=aegis.config.get('env'))
                for hydra_queue in queue_items:
                    if HydraThread.quitting.is_set(): break
                    try:
                        # Fetch rows from database queue and claim items before processing
                        if not hydra_queue: time.sleep(options.hydra_sleep); continue
                        claimed = hydra_queue.claim()
                        hydra_type = aegis.model.HydraType.get_id(hydra_queue['hydra_type_id'])
                        if aegis.config.get('hydra_debug'):
                            self.logw(claimed, "%s CLAIM HYDRA QUEUE: %s  TYPE: %s  HOST: %s  " % (self.name, hydra_queue['hydra_queue_id'], hydra_type['hydra_type_name'], hydra_queue['work_host']))
                        if not claimed: continue
                        start_t = time.time()
                        # Hydra Magic: Find the hydra_type specific function in a subclass of HydraHead
                        if not hydra_type:
                            logging.error("Missing hydra type for hydra_type_id: %s", hydra_type)
                            continue
                        if not hasattr(self, hydra_type['hydra_type_name']):
                            logging.error("Missing hydra function for hydra type: %s", hydra_type)
                            continue
                        self.timer_obj = aegis.stdlib.TimerObj()
                        aegis.stdlib.timer_start(self.timer_obj, 'hydra_queue_run')
                        self.iter_cnt += 1
                        work_fn = getattr(self, hydra_type['hydra_type_name'])
                        # Allow queue items to specify that they should run in a specific host and environment.
                        # If that's not present, or it matches the current host, run the queue. Otherwise simply unclaim and another process will claim it.
                        work_data = None
                        if hydra_queue['work_data']:
                            work_data = json.loads(hydra_queue['work_data'])
                        # Do the work
                        if hydra_type['next_run_sql']:
                            singleton = hydra_queue.singleton()
                            if singleton:
                                logging.error("%s %s already running" % (self.name, hydra_type['hydra_type_name']))
                                hydra_queue.finish()    # Not complete, since that affects status
                                continue
                        if aegis.config.get('hydra_debug'):
                            logging.warning("%s RUN HYDRA QUEUE: %s %s" % (self.name, hydra_queue['hydra_queue_id'], hydra_type['hydra_type_name']))
                        hydra_queue.incr_try_cnt()
                        hydra_queue.start()
                        result, work_cnt = work_fn(hydra_queue, hydra_type)
                        end_t = time.time()
                        exec_t_ms = (end_t - start_t) * 1000
                        if result:
                            hydra_queue.complete()
                        else:
                            logging.error("%s hydra_queue_id %s failed, will retry every 15m", self.name, hydra_queue['hydra_queue_id'])
                            hydra_queue.incr_error_cnt(minutes=15)
                            hydra_queue.unclaim()
                            continue
                        aegis.stdlib.timer_stop(self.timer_obj, 'hydra_queue_run')
                        # Worker accounting
                        logging.info(self.log_line(hydra_type, work_cnt, self.timer_msg()))
                        self.processed_cnt += work_cnt
                    except Exception as ex:
                        logging.error("Exception when working on hydra_queue_id: %s", hydra_queue['hydra_queue_id'])
                        logging.exception(ex)
                        hydra_queue.incr_error_cnt()
                        hydra_queue.unclaim()
                        self.exception_alert(ex)
                # Iterate!
                time.sleep(options.hydra_sleep)
        except Exception as ex:
            logging.exception(ex)
            self.exception_alert(ex)
        finally:
            logging.info("HydraHead %s Dying", self.name)
            self.finish()

    def timer_msg(self):
        exec_t_ms = self.timer_obj._timers.get('_hydra_queue_run_exec_s') * 1000
        net_t_ms = self.timer_obj._timers.get('_network_exec_s', 0) * 1000
        db_t_ms = self.timer_obj._timers.get('_database_exec_s') * 1000
        cpu_t_ms = exec_t_ms - net_t_ms - db_t_ms
        exec_t_str = "%.3fms" % exec_t_ms
        net_t_str = "%.3fms" % net_t_ms
        db_t_str = "%.3fms" % db_t_ms
        cpu_t_str = "%.3fms" % cpu_t_ms
        msg = " DONE %12s  |  %12s cpu  %12s db  %12s net" % (exec_t_str, cpu_t_str, db_t_str, net_t_str)
        return msg

    def log_line(self, hydra_type, work_cnt=0, msg=''):
        line = '%s %s %s %s' % (self.name, format(hydra_type['hydra_type_name'], str(self.hydra_type_maxlen)), ("%d" % work_cnt).rjust(8), msg)
        #self.logw(line, "LINE")
        return line


    def housekeeping(self, hydra_queue, hydra_type):
        logging.warning("HYDRA HOUSEKEEPING")
        # enqueue clean_build for each deploy host
        hydra_type = aegis.model.HydraType.get_name('clean_build')
        for deploy_host in options.deploy_hosts:
            hydra_queue = {'hydra_type_id': hydra_type['hydra_type_id'], 'priority_ndx': hydra_type['priority_ndx'], 'work_dttm': aegis.database.Literal("NOW()"),
                           'work_host': deploy_host, 'work_env': aegis.config.get('env')}
            hydra_queue_id = aegis.model.HydraQueue.insert_columns(**hydra_queue)



    def build_build(self, hydra_queue, hydra_type):
        # Singleton check - if someone else claimed a different hydra_queue of the same hydra_type, hydra_queue needs to unclaim and stop
        singleton = hydra_queue.singleton()
        if singleton:
            logging.error("build_build already running")
            return True, 0
        work_data = json.loads(hydra_queue['work_data'])
        build_row = aegis.model.Build.get_id(work_data['build_id'])
        # Magic to bind config.write_custom_versions onto the build, to also create the react version
        new_build = aegis.build.Build()
        exit_status = new_build.build_exec(build_row)
        if exit_status:
            logging.error("Build Failed. Version: %s" % build_row['version'])
        else:
            logging.info("Build Success. Version: %s" % build_row['version'])
            logging.info("Next step:  sudo aegis deploy --env=%s --version=%s" % (aegis.config.get('env'), build_row['version']))
        return True, 1


    def deploy_build(self, hydra_queue, hydra_type):
        # host-specific by putting hostname: key in the work_data JSON
        work_data = json.loads(hydra_queue['work_data'])
        build_row = aegis.model.Build.get_id(work_data['build_id'])
        logging.warning("Hydra Deploy Build: %s" % work_data['build_id'])
        build = aegis.build.Build()
        exit_status = build.deploy(build_row['version'], env=build_row['env'])
        # Hydra doesn't restart from supervisorctl (see build.py deploy()). Set HydraThread.quitting and allow supervisorctl to restart
        logging.warning('Stop Hydra from Hydra Deploy to let Supervisor restart Hydra')
        HydraThread.quitting.set()
        return True, 1


    def revert_build(self, hydra_queue, hydra_type):
        # host-specific by putting hostname: key in the work_data JSON
        work_data = json.loads(hydra_queue['work_data'])
        build_row = aegis.model.Build.get_id(work_data['build_id'])
        logging.warning("Hydra Revert Build: %s" % work_data['build_id'])
        build = aegis.build.Build()
        exit_status = build.revert(build_row)
        # Hydra doesn't restart from supervisorctl (see build.py deploy()). Set HydraThread.quitting and allow supervisorctl to restart
        logging.warning('Stop Hydra from Hydra Deploy to let Supervisor restart Hydra')
        HydraThread.quitting.set()
        return True, 1


    def clean_build(self, hydra_queue, hydra_type):
        # Singleton check - if someone else claimed a different hydra_queue of the same hydra_type, hydra_queue needs to unclaim and stop
        singleton = hydra_queue.singleton()
        if singleton:
            logging.error("clean_build already running")
            return True, 0
        # run on every host to clean out builds that are leftover and taking up disk space
        logging.warning("RUNNING clean_build on %s env %s", hydra_queue['work_host'], hydra_queue['work_env'])
        build = aegis.build.Build()
        # Delete any builds that are undeployed or deleted and older than a week.
        dead_builds = aegis.model.Build.scan_dead_builds()
        for dead_build in dead_builds:
            build.clean(dead_build)
        # Keep the 5 most recently deployed builds per environment. Delete the rest.
        envs = [env['env'] for env in aegis.model.Build.deployed_envs()]
        for env in envs:
            # Don't delete the builds with version <env>-admin
            stale_builds = [build for build in aegis.model.Build.scan_stale_builds(env) if not build['version'].startswith('%s-admin' % env)]
            for stale_build in stale_builds[5:]:
                #logging.error("STALE BUILDS need to be handled by my recent BY ENV or else we could delete in-use old ones")
                self.logw(stale_build['build_id'], "STALE BUILD - cleaning it up")
                self.logw(env, "ENV")
                self.logw(stale_build['version'], "VERSION")
                self.logw(stale_build['deploy_dttm'], "DEPLOY DTTM")
                build.clean(stale_build)
        return True, 1


class Hydra(HydraThread):

    def __init__(self):
        self.hydra_id = options.hydra_id
        self.thread_name = 'Hydra-%02d' % options.hydra_id
        HydraThread.__init__(self, name=self.thread_name)
        self.num_heads = 3
        self.heads = []
        self.hydra_head_cls = HydraHead
        self.stuck_minutes = aegis.config.get('hydra_stuck_minutes') or 15


    def spawn_heads(self):
        # When any of the hydra's heads are cut off, a new one will grow in its place.
        self.heads = [head for head in self.heads if head.is_alive()]
        for ndx in range(0, self.num_heads - len(self.heads)):
            time.sleep(1)
            head = self.hydra_head_cls(ndx)
            head.start()
            self.heads.append(head)


    def process(self):
        logging.info("Spawning %s" % self.name)
        # When starting up, hydra_id 0 clears claims before spawning heads.
        if self.hydra_id == 0:
            logging.warning("%s clearing stale claims" % self.name)
            aegis.model.HydraType.clear_claims(minutes=self.stuck_minutes)
            aegis.model.HydraQueue.clear_claims(minutes=self.stuck_minutes)
            # If the hydra_type_id for this queue item has next_run_sql then it should be a singleton across the hydras.
            # This means set hydra_type['status'] = 'running' and set it back to 'live' after completion.
            logging.warning("%s clearing running jobs over 45 minutes old" % self.name)
            aegis.model.HydraType.clear_running()
        try:
            self.spawn_heads()
            while(not HydraThread.quitting.is_set()):
                self.iter_cnt += 1
                try:
                    # Batch Loop: scan hydra_type for runnable batches
                    for hydra_type in aegis.model.HydraType.scan():
                        if HydraThread.quitting.is_set(): break
                        # Check if the task is runnable
                        runnable = aegis.model.HydraType.get_runnable(hydra_type['hydra_type_id'], aegis.config.get('env'))
                        if aegis.config.get('hydra_debug') and runnable:
                            logging.warning("%s FOUND RUNNABLE %s %s" % (self.name, hydra_type['hydra_type_name'], aegis.config.get('env')))
                        if runnable:
                            claimed = hydra_type.claim()
                            if aegis.config.get('hydra_debug'):
                                self.logw(claimed, "%s CLAIM HYDRA TYPE: %s %s  " % (self.name, hydra_type['hydra_type_id'], hydra_type['hydra_type_name']))
                            if not claimed: continue
                            # Set up a hydra_queue row to represent the work and re-schedule the batch's next run
                            hydra_queue = {}
                            hydra_queue['hydra_type_id'] = hydra_type['hydra_type_id']
                            hydra_queue['priority_ndx'] = hydra_type['priority_ndx']
                            hydra_queue['work_dttm'] = aegis.database.Literal("NOW()")
                            hydra_queue['work_env'] = hydra_type.get('run_env', aegis.config.get('env'))
                            if hydra_type.get('run_host'):
                                hydra_queue['work_host'] = hydra_type['run_host']
                            hydra_queue_id = aegis.model.HydraQueue.insert_columns(**hydra_queue)
                            hydra_type.schedule_next()
                            _hydra_type = aegis.model.HydraType.get_id(hydra_type['hydra_type_id'])
                            if aegis.config.get('hydra_debug'):
                                self.logw(_hydra_type['next_run_dttm'], "SCHEDULE NEXT ID: %s  Type: %s  " % (_hydra_type['hydra_type_id'], _hydra_type['hydra_type_name']))
                            # Clean out queue then sleep depending on how much work there is to do
                            purged_completed = aegis.model.HydraQueue.purge_completed()
                            #if purged_completed:
                            #    logging.warning("%s queue purge deleted %s hydra_queue" % (self.thread_name, purged_completed))
                            # Log if there are expired queue items in the past...
                            past_items = aegis.model.HydraQueue.past_items(minutes=self.stuck_minutes)
                            if past_items and len(past_items):
                                #logging.error("HydraQueue has %s stuck items", len(past_items))
                                for past_item in past_items:
                                    past_item_type = aegis.model.HydraType.get_id(past_item['hydra_type_id'])
                                    logging.error("Running stuck hydra_queue_id: %s  hydra_type_name: %s", past_item['hydra_queue_id'], past_item_type['hydra_type_name'])
                                    past_item.run_now()
                            # Any hydra_type claimed since the next_run_dttm and over 5m old are stuck. Automatically unclaim them.
                            past_items = aegis.model.HydraType.past_items(minutes=self.stuck_minutes)
                            if past_items and len(past_items):
                                #logging.error("HydraType has %s stuck items", len(past_items))
                                for past_item in past_items:
                                    logging.error("Unclaiming stuck hydra_type_id: %s  hydra_type_name: %s", past_item['hydra_type_name'], past_item['hydra_type_name'])
                                    past_item.unclaim()

                # Better handling of AdminShutdown, OperationalError, to capture structured and complete data to logs and alerts.
                except (aegis.database.PgsqlAdminShutdown, aegis.database.PgsqlOperationalError, aegis.database.MysqlOperationalError, aegis.database.MysqlInterfaceError) as ex:
                    aegis.stdlib.loge(ex, "Database is Down. Pause 3 seconds.")
                    logging.exception(ex)
                    self.exception_alert(ex)
                    time.sleep(3)
                except Exception as ex:
                    logging.exception("Batch had an inner loop failure.")
                    self.exception_alert(ex)
                # Iterate!
                #logging.warning("The great hydra sleeps...")
                time.sleep(options.hydra_sleep)
                self.spawn_heads()

        except Exception as ex:
            logging.exception(ex)
            traceback.print_exc()
            self.exception_alert(ex)


        finally:
            self.finish()


if __name__ == "__main__":
    tornado.options.parse_command_line()
    hydra = Hydra()
    hydra.start()
    hydra.main_thread()
    sys.exit(0)
