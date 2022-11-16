#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Aegis is your shield to protect you on the Brave New Web

# Python Imports
import argparse
import ast
import functools
import glob
import logging
import os
import pwd
import sys

# Extern Imports
import tornado.options
from tornado.options import define, options

# Project Imports
import aegis.stdlib
import aegis.build
import aegis.config

# Load project config via VIRTUAL_ENV and naming convention, or by calling virtualenv binary directly
venv = os.environ.get('VIRTUAL_ENV')
if venv:
    # Running from within a virtualenv
    repo_dir = os.path.dirname(venv)
    src_dir = os.path.join(repo_dir, os.path.split(repo_dir)[-1])
    sys.path.insert(0, src_dir)
    #print("running within virtualenv")
    import config
elif sys.argv[0] == 'virtualenv/bin/aegis':
    # Running by calling the virtualenv binary directly
    repo_dir = os.getcwd()
    src_dir = os.path.join(repo_dir, os.path.split(repo_dir)[-1])
    sys.path.insert(0, src_dir)
    #print("running from aegis cmdline")
    import config
elif sys.argv[0] == '/usr/local/bin/aegis':
    repo_dir = os.getcwd()
    #print("running from /usr/local/bin")
    if os.path.exists(os.path.join(repo_dir, '.git')):
        src_dir = os.path.join(repo_dir, os.path.split(repo_dir)[-1])
        sys.path.insert(0, src_dir)
        import config
    else:
        logging.error("Can't detect your app dir. Be in the source root, next to .git dir.")
        sys.exit(1)
else:
    print(aegis.stdlib.cstr("Running in non-standard context. Going to wing it and import config. Hope this works!", 'yellow'))
    print(aegis.stdlib.cstr("Make sure you're in the source root, next to the .git dir.", 'yellow'))
    repo_dir = os.getcwd()
    src_dir = os.path.join(repo_dir, os.path.split(repo_dir)[-1])
    sys.path.insert(0, src_dir)
    import config


### Note to self: aegis create will work better if the core web is web.py so we don't clobber snowballin.py
# Needs templates dir, etc
# Prompt y/n to clobber with diff
# Also need aegis install, to make system admin faster
# Should all start with the /aegis stuff
# Also the sql should all be there for hydra, reports, etc



# Create a new spinoff of aegis
def create(parser):
    args = parser.parse_args()
    if not args.appname or not args.domain:
        logging.error("aegis create requires --appname and --domain")
        sys.exit()
    app_name = args.appname[0]
    domain = args.domain[0]
    aegis.stdlib.logw("AEGIS CREATE  %s  %s" % (app_name, domain))
    aegis_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
    src_dir = os.path.dirname(aegis_dir)
    template_vars = {'app_name': app_name, 'aegis_domain': domain}
    create_dir = os.path.join(src_dir, app_name)
    #aegis.stdlib.logw(create_dir, "CREATE DIR")
    #if os.path.exists(create_dir):
    #    logging.error("AEGIS     Sorry that directory exists already. Exiting.")
    #    sys.exit(1)

    # If the directory exists prompt the user
    # You can run aegis create again to produce a new create in your repo. Then you can look at git diff to resolve and differences.

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
        logging.warning(rebasedir)
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
                # XXX TODO diff output between one on filesystem
                # XXX maybe prompt y/n to overwrite
                with open(rebasepath, 'w') as writefd:
                    writefd.write(output)
    print ("GREAT SUCCESS!!")
    # git create and push
    # virtualenv and setup.py
    # <appname>/<appname>.py


# Diff and apply system configs to /etc and /srv
def install(parser):
    aegis.stdlib.logw(parser, "INSTALL ARG PARSER")


def schema(parser):
    # Argument Handling
    args = parser.parse_args()
    schema_args = {'hostname': args.hostname, 'dry_run': ast.literal_eval(args.dry_run), 'env': aegis.config.get('env')}
    if not schema_args.get('env') or not schema_args.get('hostname'):
        logging.error("aegis schema requires --env and --hostname")
        aegis.stdlib.loge(schema_args, "SCHEMA ARGS")
        sys.exit(1)
    # Command line options and sanity checking
    if not schema_args['hostname']:
        logging.error("Please specify hostname to apply schema to, ie dev.codebug.com")
        exit(1)
    config.initialize()
    config.apply_hostname(schema_args['hostname'])
    if aegis.database.pgsql_available:
        database = options.pg_database
    elif aegis.database.mysql_available:
        database = options.mysql_database
    logging.info("Running schema.py   Env: %s   Hostname: %s   Database: %s   Dry Run: %s",
                 schema_args['env'], schema_args['hostname'], database, schema_args['dry_run'])
    if not database:
        logging.error("Database isn't configured for this hostname")
        exit(1)
    # Prime the database and sql_diff
    try:
        dbnow = aegis.database.dbnow()
        logging.warning("Database Standard Time: %s", dbnow['now'])
        if aegis.database.pgsql_available:
            results = aegis.database.db().get("SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = 'sql_diff')")
        elif aegis.database.mysql_available:
            results = aegis.database.db().get("SELECT * FROM information_schema.tables WHERE TABLE_SCHEMA=%s AND TABLE_NAME='sql_diff'", options.mysql_database)
            results = {'exists': bool(results)}
        if not results['exists']:
            logging.warning("Creating sql_diff table since it doesn't exist yet.")
            aegis.model.SqlDiff.create_table()
    except aegis.database.PgsqlOperationalError as ex:
        logging.error("Could not connect to database. Do you need to log into postgres and run:")
        logging.error("postgres=# CREATE USER %s WITH PASSWORD '%s';" % (options.pg_username, options.pg_password))
        logging.error("postgres=# GRANT %s TO <root>;    # where root like doadmin, awsadmin" % (options.pg_username))
        logging.error("postgres=# CREATE DATABASE %s OWNER=%s;" % (options.pg_database, options.pg_username))
        exit(1)
    except Exception as ex:
        logging.error("Unknown Error Occurred")
        logging.exception(ex)
        exit(1)
    def diff_sort_cmp(x, y):
        xx = int(x.split('diff')[1].split('.sql')[0])
        yy = int(y.split('diff')[1].split('.sql')[0])
        return xx - yy
    def patch_diffs(sql_dir, prefix='diff'):
        if not os.path.exists(sql_dir):
            logging.error('No patch dir found at: %s', sql_dir)
            sys.exit(1)
        patches = [g.split('/')[-1] for g in glob.glob(sql_dir + '/' + prefix + '*.sql')]
        patchnums = [patch.lstrip(prefix).rstrip('.sql') for patch in patches]
        patchnums.sort()
        diffs = ['%s%s.sql' % (prefix, patchnum) for patchnum in patchnums]
        diffs = sorted(diffs, key=functools.cmp_to_key(diff_sort_cmp))
        return diffs
    # Read sql_diffs from filesystem and perform schema migrations
    sql_dir = options.basedir
    schema_path = aegis.config.get('schema_path')
    if schema_path:
        sql_dir = os.path.join(sql_dir, schema_path)
    sql_dir = os.path.join(sql_dir, 'sql')
    diff_files = patch_diffs(sql_dir)
    # Read state from database, INSERT INTO sql_diff for unknown diffs
    sql_diff_rows = aegis.model.SqlDiff.scan()
    sql_diff_map = aegis.model.SqlDiff.map_items(sql_diff_rows, 'sql_diff_name')
    for diff_file in diff_files:
        if diff_file not in sql_diff_map:
            logging.warning("Inserting diff: %s", diff_file)
            aegis.model.SqlDiff.insert(diff_file)
    # Apply any unapplied diffs
    for patch in aegis.model.SqlDiff.scan_unapplied():
        filename = os.path.join(sql_dir, patch['sql_diff_name'])
        sql = open(filename).read().replace('%', '%%')
        try:
            if schema_args['dry_run']:
                logging.warning("[Dry Run] diff:  %s  from: %s" % (patch['sql_diff_name'], filename))
            else:
                logging.warning("Applying diff:  %s  from: %s" % (patch['sql_diff_name'], filename))
                aegis.database.db().execute(sql)
                aegis.model.SqlDiff.mark_applied(patch['sql_diff_name'])
        except Exception as ex:
            logging.exception(ex)
            logging.error('Query was: %s', sql)
            exit(1)


def build(parser):
    # Argument Handling
    args = parser.parse_args()
    build_args = {'branch': args.branch, 'revision': args.revision, 'env': aegis.config.get('env'), 'build_target': args.build_target}
    if not aegis.config.get('env') or not(build_args['branch'] or build_args['revision']):
        logging.error("aegis build requires --env and one of --branch or --revision")
        aegis.stdlib.loge(aegis.config.get('env'), "ENV")
        aegis.stdlib.loge(build_args, "BUILD ARGS")
        sys.exit(1)
    # Require sudo to build, set real and effective uid and gid, as well as HOME for www-data user
    if not os.geteuid() == 0:
        logging.error('You need root privileges, please run it with sudo.')
        sys.exit(1)
    config.initialize()
    if args.hostname:
        config.apply_hostname(args.hostname)
    pw = pwd.getpwnam('www-data')
    os.putenv('HOME', pw.pw_dir)
    os.setregid(pw.pw_gid, pw.pw_gid)
    os.setreuid(pw.pw_uid, pw.pw_uid)
    # Set up build
    logging.info("Running aegis build   Env: %s   Branch: %s   Revision: %s", aegis.config.get('env'), build_args['branch'], build_args['revision'])
    new_build = aegis.build.Build()
    build_row = new_build.create(build_args)
    if build_row.get('error'):
        logging.error(build_row['error'])
        sys.exit(1)
    # Running build itself
    exit_status = new_build.build_exec(build_row)
    build_row = aegis.model.Build.get_id(build_row['build_id'])
    if exit_status:
        logging.error("Build Failed. Version: %s" % build_row['version'])
    else:
        logging.info("Build Success. Version: %s" % build_row['version'])
        logging.info("Next step:  sudo aegis deploy --env=%s --version=%s" % (aegis.config.get('env'), build_row['version']))
    sys.exit(exit_status)


def deploy(parser):
    # Argument Handling
    args = parser.parse_args()
    version = args.version
    env = args.env
    if not version or not env:
        aegis.stdlib.logw(version, "VERSION")
        aegis.stdlib.logw(env, "ENV")
        logging.error("aegis deploy requires --version and --env")
        sys.exit()
    # Require sudo to build, set real and effective uid and gid, as well as HOME for www-data user
    if not os.geteuid() == 0:
        logging.error('You need root privileges, please run it with sudo.')
        sys.exit(1)
    config.initialize()
    if args.hostname:
        config.apply_hostname(args.hostname)
    pw = pwd.getpwnam('www-data')
    os.putenv('HOME', pw.pw_dir)
    os.setregid(pw.pw_gid, pw.pw_gid)
    os.setreuid(pw.pw_uid, pw.pw_uid)
    # Make it so
    logging.info("Running aegis deploy   Version: %s   Env: %s", version, env)
    build = aegis.build.Build()
    message = None
    while not message:
        message = input(aegis.stdlib.cstr('Type in release notes for the deploy notification:\n', 'white'))
    # Save the user message and start the deploy/revert
    build_row = aegis.model.Build.get_version(version)
    build_row.set_message(message, 'deploy')
    build_row = aegis.model.Build.get_version(version)
    aegis.build.Build.start_deploy(build_row, os.getenv('SUDO_USER'))
    build.deploy(version, env=env)


def revert(parser):
    # Argument Handling
    args = parser.parse_args()
    env = args.env
    if not env:
        aegis.stdlib.logw(env, "ENV")
        logging.error("aegis revert requires --env")
        sys.exit()
    # Require sudo to build, set real and effective uid and gid, as well as HOME for www-data user
    if not os.geteuid() == 0:
        logging.error('You need root privileges, please run it with sudo.')
        sys.exit(1)
    pw = pwd.getpwnam('www-data')
    os.putenv('HOME', pw.pw_dir)
    os.setregid(pw.pw_gid, pw.pw_gid)
    os.setreuid(pw.pw_uid, pw.pw_uid)
    # Make it so
    logging.info("Running aegis revert   Env: %s", env)
    build = aegis.build.Build()
    message = None
    while not message:
        message = input(aegis.stdlib.cstr('Type in release notes for the deploy notification:\n', 'white'))
    # Save the user message and start the deploy/revert
    build_row = aegis.model.Build.get_live_build(env)
    build_row.set_message(message, 'revert')
    build_row = aegis.model.Build.get_id(build_row['build_id'])
    aegis.build.Build.start_revert(build_row, os.getenv('SUDO_USER'))
    build_row = aegis.model.Build.get_id(build_row['build_id'])
    build_row.set_output('revert', '')
    build.revert(build_row)


def initialize():
    # if branch, revision, version, env don't exist, add them
    if not aegis.config.get('branch'):
        define('branch', default=None, help='git branch name', type=str)
    if not aegis.config.get('revision'):
        define('revision', default=None, help='git revision hash', type=str)
    if not aegis.config.get('version'):
        define('version', default=None, help='git version name', type=str)
    if not aegis.config.get('dry_run'):
        define('dry_run', default='True', help='make no changes', type=str)
    #aegis.stdlib.logw(aegis.config.get('env'), "AEGIS ENV")
    tornado.options.parse_command_line(sys.argv[1:])
    #aegis.stdlib.logw(aegis.config.get('env'), "AEGIS ENV PARSED")
    #try:
    #    config.initialize(args=sys.argv[1:])
    #except Exception as ex:
    #    logging.exception(ex)
    #    # No config, such as during aegis create shell command
    #    remaining = tornado.options.parse_command_line(sys.argv[1:])
    #    print(aegis.stdlib.cstr("Remaining arguments: %s" % remaining, 'red'))


def main():
    parser = argparse.ArgumentParser(description='Create your shield.')
    parser.add_argument('cmd', metavar='<command>', type=str, nargs=1, help='What to do: [create, install, schema, build, deploy, revert]')
    parser.add_argument('--branch', metavar='<branch>', type=str, help='git branch name')
    parser.add_argument('--revision', metavar='<revision>', type=str, help='git revision hash')
    parser.add_argument('--env', metavar='<env>', type=str, help='primary environment name')
    parser.add_argument('--build_target', metavar='<build_target>', default='application', type=str, help='build target  <application, admin>')
    parser.add_argument('--version', metavar='<version>', type=str, help='program version tag')
    parser.add_argument('--appname', metavar='<appname>', type=str, nargs=1, help='code name for application')
    parser.add_argument('--domain', metavar='<domain>', type=str, nargs=1, help='domain to create application')
    parser.add_argument('--hostname', metavar='<hostname>', type=str, help='hostname to specify configs')
    parser.add_argument('--dry_run', metavar='<dry_run>', type=str, default='True', help='make no changes')
    args = parser.parse_args()
    cmd = args.cmd[0]
    # Do something
    if cmd == 'create':
        return create(parser)
    elif cmd == 'install':
        return install(parser)
    elif cmd == 'schema':
        return schema(parser)
    elif cmd == 'build':
        return build(parser)
    elif cmd == 'deploy':
        return deploy(parser)
    elif cmd == 'revert':
        return revert(parser)
    else:
        logging.error("NOT IMPLEMENTED... YET")
        return 127

if __name__ == "__main__":
    # Called from repository checkout, for example ./aegis/aegis_.py
    initialize()
    retval = main()
    sys.exit(retval)
elif __name__ == 'aegis.aegis_':
    # Called from entry point, likely from setup.py installation
    initialize()
    retval = main()
    sys.exit(retval)
else:
    # Not entirely sure how it was called
    initialize()
    aegis.stdlib.logw(__name__, "Called by __name__")
    sys.exit(126)
