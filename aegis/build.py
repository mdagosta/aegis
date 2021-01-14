# It's really its own thing
#
# Mainly a web interface to do a build. Command line backup/repair.

# Python Imports
import configparser
import logging
import os
import socket
import sys
import time
import traceback

# Extern Imports
import tornado.options
from tornado.options import define, options

# Project Imports
import aegis.stdlib
import aegis.model


class Build:
    def __init__(self, write_custom_versions_fn=None):
        self.logw = aegis.stdlib.logw
        self.write_custom_versions_fn = write_custom_versions_fn


    # Shell output handling
    def shell_exec(self, cmd, cwd, output_tx_field, env=None):
        exec_output = "%s@%s:%s> %s" % (self.username, self.host, cwd, cmd)
        stdout, stderr, exit_status = aegis.stdlib.shell(cmd, cwd=cwd, env=env)
        if stdout:
            exec_output += '\n%s' % stdout
        if stderr:
            exec_output += "\n%s" % stderr
        exec_output += "\n"
        if sys.stdout.isatty():
            if exit_status:
                logging.error(exec_output.rstrip())
            else:
                logging.info(exec_output.rstrip())
        self.output_tx += exec_output
        if output_tx_field == 'build_output_tx':
            self.build.set_build_output(self.output_tx)
        elif output_tx_field == 'deploy_output_tx':
            self.build.set_deploy_output(self.output_tx)
        elif output_tx_field == 'revert_output_tx':
            self.build.set_revert_output(self.output_tx)
        self.build = aegis.model.Build.get_id(self.build['build_id'])
        if exit_status:
            self.done_exec(output_tx_field, exit_status)
        return exit_status

    def done_exec(self, output_tx_field, exit_status=0):
        end_t = time.time()
        exec_t = end_t - self.start_t
        exit_line = "\n  [ Exit %s   (%4.2f sec) ]" % (exit_status, exec_t)
        if sys.stdout.isatty():
            if exit_status:
                logging.error(exit_line.rstrip())
            else:
                logging.info(exit_line.rstrip())
        self.output_tx += exit_line
        if output_tx_field == 'build_output_tx':
            self.build.set_build_output(self.output_tx, exit_status)
        elif output_tx_field == 'deploy_output_tx':
            self.build.set_deploy_output(self.output_tx, exit_status)
        elif output_tx_field == 'revert_output_tx':
            self.build.set_revert_output(self.output_tx, exit_status)
        return exit_status

    def build_exec(self, cmd, cwd, env=None):
        exit_status = self.shell_exec(cmd, cwd, 'build_output_tx', env)
        return exit_status

    def deploy_exec(self, cmd, cwd, env=None):
        exit_status = self.shell_exec(cmd, cwd, 'deploy_output_tx', env)
        return exit_status

    def revert_exec(self, cmd, cwd, env=None):
        exit_status = self.shell_exec(cmd, cwd, 'revert_output_tx', env)
        return exit_status


    # Create a new build
    def create(self, build_args):
        if not (build_args.get('branch') or build_args.get('revision')):
            aegis.stdlib.logw(build_args, "BUILD ARGS")
            return {'error': "aegis.build.Build.create(build_args) must have 'env' and one of 'branch' or 'revision'"}
        if not build_args['revision']:
            build_args['revision'] = 'HEAD'
        self.build_id = aegis.model.Build.insert_columns(**build_args)
        build_row = aegis.model.Build.get_id(self.build_id)
        return build_row

    # Perform build and distribute to hosts
    def build_git_venv_yarn(self, build):
        try:
            self.build = build
            self.start_t = time.time()
            self.output_tx = ''
            # Environment
            self.src_dir = aegis.config.get('src_dir')
            self.src_repo = os.path.join(self.src_dir, options.program_name)
            self.username, stderr, exit_status = aegis.stdlib.shell('whoami', cwd=self.src_dir)
            self.host = socket.gethostname()
            refspec = build['branch']
            if build['revision'] != 'HEAD':
                refspec = build['revision']
            # Make a local clone of the repository from origin so we don't have to clone entire repository every time
            if not os.path.exists(self.src_repo):
                if self.build_exec("git clone --progress git@%s %s" % (aegis.config.get('git_repo'), options.program_name), cwd=self.src_dir):
                    return
            # Fetch all the changes to repo and set the correct branch and revision
            if self.build_exec("git fetch --all", cwd=self.src_repo):
                return
            # Reset in case there are version changes from previous builds
            if self.build_exec("git reset --hard", cwd=self.src_repo):
                return
            if self.build_exec("git checkout %s" % (refspec), cwd=self.src_repo):
                return
            if self.build_exec("git pull --commit --ff", cwd=self.src_repo):
                return
            if build['revision'] == 'HEAD':
                commit_hash, stderr, exit_status = aegis.stdlib.shell('git rev-parse HEAD', cwd=self.src_repo)
                self.build.set_revision(commit_hash)
            # Generate new version number before cloning the new version tag into build directory
            self.new_version()
            env = {"GIT_COMMITTER_NAME": options.git_committer_name, "GIT_COMMITTER_EMAIL": options.git_committer_email,
                   "GIT_AUTHOR_NAME": options.git_committer_name, "GIT_AUTHOR_EMAIL": options.git_committer_email}
            if self.build_exec("git commit -m 'version %s' %s" % (self.next_tag, ' '.join(self.version_files)), cwd=self.src_repo, env=env):
                return
            if self.build_exec("git tag %s" % self.next_tag, cwd=self.src_repo):
                return
            if self.build_exec("git push", cwd=self.src_repo):
                return
            if self.build_exec("git push --tags", cwd=self.src_repo):
                return
            self.build.set_version(self.next_tag)
            # Clone a fresh build into directory named by version tag
            app_dir = os.path.join(options.deploy_dir, options.program_name)
            self.build_dir = os.path.join(app_dir, self.next_tag)
            if os.path.exists(self.build_dir):
                if self.build_exec("rm -rf %s" % build_dir, cwd=app_dir):
                    return
            if self.build_exec("git clone %s %s" % (self.src_repo, self.build_dir), cwd=app_dir):
                return
            # Set up virtualenv
            if self.build_exec("virtualenv --python=/usr/bin/python3 --system-site-packages virtualenv", cwd=self.build_dir):
                return
            if self.build_exec("virtualenv/bin/pip --cache-dir .cache install -e .", cwd=self.build_dir):
                return
            # Set up and run yarn if it's installed
            self.yarn, stderr, exit_status = aegis.stdlib.shell('which yarn', cwd=self.src_dir)
            if self.yarn:
                if self.build_exec("nice yarn install", cwd=self.build_dir):
                    return
                if self.build_exec("nice yarn run %s --cache-folder /srv/www/.cache/yarn" % options.env, cwd=self.build_dir):
                    return
                build_output_file = os.path.join(self.build_dir, options.build_output_file % {'tag': self.next_tag})
                if os.path.exists(build_output_file):
                    build_size = os.path.getsize(build_output_file)
                    if build_size:
                        self.build.set_build_size(build_size)
            # Rsync the files to the servers if it's configured
            rsync_hosts = [rh for rh in aegis.config.get('deploy_hosts') if rh != self.host]
            for rsync_host in rsync_hosts:
                cmd = "rsync -q --password-file=/etc/rsync.password -avzhW %s www-data@%s::%s" % (self.build_dir, rsync_host, options.rsync_module)
                if self.build_exec(cmd, cwd=self.build_dir):
                    return
        except Exception as ex:
            logging.exception(ex)
            self.output_tx += "\n%s" % traceback.format_exc()
            self.build.set_build_output(self.output_tx, 1)
            return self.done_exec('build_output_tx', 1)
        return self.done_exec('build_output_tx')

    def new_version(self):
        self.branch = self.build['branch']
        self.section = '%s' % self.branch
        self.config = configparser.ConfigParser()
        self.src_repo_app = os.path.join(self.src_repo, options.program_name)
        self.version_file = os.path.join(self.src_repo_app, 'version.cfg')
        self.config.read(self.version_file)
        try:
            self.version = self.str_version(self.config.get(self.section, 'version'))
        except configparser.NoSectionError as ex:
            self.config.add_section(self.section)
            self.version = [0, 0, 0]
        self.next_version = self.incr_version(*self.version)
        self.tag = '%s-%s' % (self.branch, self.version_str(*self.version))
        self.next_tag = '%s-%s' % (self.branch, self.version_str(*self.next_version))
        self.write_py_version()
        self.version_files += self.write_custom_versions_fn(self.next_tag, self.src_repo_app)

    def incr_version(self, x, y, z):
        if z < 99:
            return x, y, z+1
        z = 0
        if y < 9:
            return x, y+1, z
        y = 0
        return x+1, y, z

    def str_version(self, cfg_version):
        version_number = cfg_version.split('-')[-1]
        return tuple([int(subversion) for subversion in version_number.split('.')])

    def version_str(self, x, y, z):
        return '%s.%s.%s' % (x, y, z)

    def write_py_version(self):
        self.config.set(self.section, 'version', self.next_tag)
        fd = open(self.version_file, 'w')
        self.config.write(fd)
        fd.close()
        self.version_files = [self.version_file]


    def deploy(self, version, env=None, output_tx_field='deploy_output_tx'):
        # Environment Settings
        self.build = aegis.model.Build.get_version(version)
        self.build = aegis.model.Build.get_id(self.build['build_id'])
        app_dir = os.path.join(options.deploy_dir, options.program_name)
        build_dir = os.path.join(app_dir, self.build['version'])
        live_symlink = os.path.join(app_dir, aegis.config.get('env'))
        self.start_t = time.time()
        self.output_tx = ''
        self.username, stderr, exit_status = aegis.stdlib.shell('whoami')
        self.host = socket.gethostname()
        # What to restart
        processes, stderr, exit_status = aegis.stdlib.shell("sudo /usr/bin/supervisorctl status")
        processes = [process.split(' ')[0] for process in processes.splitlines() if process.split(':')[0].endswith('_'+aegis.config.get('env'))]
        # Remove and re-link
        if self.shell_exec("rm -f %s" % live_symlink, output_tx_field=output_tx_field, cwd=app_dir):
            return
        if self.shell_exec("ln -s %s %s" % (build_dir, live_symlink), output_tx_field=output_tx_field, cwd=app_dir):
            return
        # Restart processes
        for process in processes:
            if self.shell_exec("sudo /usr/bin/supervisorctl restart %s" % (process), output_tx_field=output_tx_field, cwd=app_dir):
                self.logw(process, "ERROR RESTARTING PROCESS")
                return
        # Set the previous version so we know what to revert back to, and mark it deployed
        self.build = aegis.model.Build.get_id(self.build['build_id'])
        live_build = aegis.model.Build.get_live_build()
        if live_build:
            self.build.set_previous_version(live_build['version'])
            self.build = aegis.model.Build.get_id(self.build['build_id'])
        self.build.set_deployed()
        return self.done_exec(output_tx_field)


    def revert(self, env=None):
        self.output_tx = ''
        self.start_t = time.time()
        output_tx_field = 'revert_output_tx'
        self.build = aegis.model.Build.get_live_build()
        if not self.build:
            logging.error("There is currently no live build.")
            sys.exit(1)
        if not self.build['previous_version']:
            self.output_tx = "Current live build doesn't have a previous_version to revert to."
            logging.error(self.output_tx)
            return self.done_exec(output_tx_field, 1)
        # Mark the build reverted, then run the deploy on the previous_version
        self.build.set_reverted()
        return self.deploy(self.build['previous_version'], env=env, output_tx_field=output_tx_field)
