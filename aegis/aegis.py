#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Aegis is your shield to protect you on the Brave New Web

import argparse
import logging
import os
import stdlib
import sys

parser = argparse.ArgumentParser(description='Create your shield.')
parser.add_argument('cmd', metavar='<command>', type=str, nargs=1, help='What to do: [create]')
parser.add_argument('--appname', metavar='<appname>', type=str, nargs=1, help='Name for the forked copy')
parser.add_argument('--domain', metavar='<domain>', type=str, nargs=1, help='Domain for the forked copy')
#parser.add_argument('values', metavar='<value>', type=str, nargs='+', help='Whatever goes with the cmd')
#values = args.values
args = parser.parse_args()
cmd = args.cmd[0]
if args.cmd == 'create' and not args.appname or not args.domain:
    logging.error("aegis create requires --appname and --domain")
    sys.exit()

app_name = args.appname[0]
domain = args.domain[0]
stdlib.logw("AEGIS  %s  %s  %s" % (cmd, app_name, domain))
aegis_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
src_dir = os.path.dirname(aegis_dir)


def create(cmd, app_name, domain):
    template_vars = {'app_name': app_name, 'aegis_domain': domain}
    create_dir = os.path.join(src_dir, app_name)
    #stdlib.logw(create_dir, "CREATE DIR")
    #if os.path.exists(create_dir):
    #    logging.error("AEGIS     Sorry that directory exists already. Exiting.")
    #    sys.exit(1)
    if not os.path.exists(create_dir):
        os.mkdir(create_dir)
    create_etc_dir = os.path.join(create_dir, 'etc')
    if not os.path.exists(create_etc_dir):
        os.mkdir(create_etc_dir)
    # Now walk tmpl/etc
    tmpl_dir = os.path.join(aegis_dir, 'aegis', 'tmpl')
    for entry in os.walk(tmpl_dir):
        basedir, subdirs, files = entry
        rebasedir = create_dir + basedir[basedir.find('aegis/tmpl')+10:]
        if rebasedir.endswith('/aegis'):
            rebasedir = rebasedir[:-6] + '/' + app_name
        if not os.path.exists(rebasedir):
            os.mkdir(rebasedir)
        for filename in files:
            filepath = os.path.join(basedir, filename)
            with open(filepath, 'r') as fd:
                # iterate a dictionary of vars and replace vars
                output = fd.read()
                for var, val in template_vars.items():
                    output = output.replace('{{%s}}' % var, val)
                rebase_filename = filename
                if filename == 'aegis.py':
                    rebase_filename = app_name + '.py'
                if filename == 'aegis.conf':
                    rebase_filename = app_name + '.conf'
                if filename == 'aegis_dev.conf':
                    rebase_filename = app_name + '_dev.conf'
                if filename == 'aegis_prod.conf':
                    rebase_filename = app_name + '_prod.conf'
                rebasepath = os.path.join(rebasedir, rebase_filename)
                with open(rebasepath, 'w') as writefd:
                    writefd.write(output)
    print ("GREAT SUCCESS!!")
    # git create and push
    # virtualenv and setup.py
    # epl/epl.py

if __name__ == "__main__":
    if cmd == 'create':
        create(cmd, app_name, domain)
    if cmd == 'apply':
        logging.warn("APPLY ... ETC")
    sys.exit()
