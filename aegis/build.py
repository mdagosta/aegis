# It's really its own thing
#
# Mainly a web interface to do a build. Command line backup/repair.

# Python Imports
import configparser
import logging
import os
import requests
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


# TODO
# - deploy, revert, and delete on web should have a confirm screen, with user message for deploy notifications
# - hydra clean build: started but needs sorting and action-taking
# - multiple-notification of deploy needs to be sorted out into aegis_ and hydra clients

class Build:
    def __init__(self, user=None):
        self.logw = aegis.stdlib.logw
        self.user = user


    # Create a new build
    def create(self, build_args):
        if not (build_args.get('branch') or build_args.get('revision')) or not build_args.get('env'):
            return {'error': "aegis.build.Build.create(build_args) must have 'env' and one of 'branch' or 'revision'"}
        if not build_args['revision']:
            build_args['revision'] = 'HEAD'
        self.build_id = aegis.model.Build.insert_columns(**build_args)
        self.build_row = aegis.model.Build.get_id(self.build_id)
        return self.build_row


    # Perform build and distribute to hosts
    def build_exec(self, build_row):
        try:
            self.build_row = build_row
            self.start_t = time.time()
            # Environment
            self.src_dir = aegis.config.get('src_dir')
            self.src_repo = os.path.join(self.src_dir, options.program_name)
            self.username, stderr, exit_status = aegis.stdlib.shell('whoami', cwd=self.src_dir)
            self.host = socket.gethostname()
            refspec = build_row['branch']
            if build_row['revision'] != 'HEAD':
                refspec = build_row['revision']
            # Make a local clone of the repository from origin so we don't have to clone entire repository every time
            if not os.path.exists(self.src_repo):
                if self._shell_exec("git clone --progress git@%s %s" % (aegis.config.get('git_repo'), options.program_name), cwd=self.src_dir, build_step='build'):
                    return
            # Fetch all the changes to repo and set the correct branch and revision
            if self._shell_exec("git fetch --all", cwd=self.src_repo, build_step='build'):
                return
            # Reset in case there are version changes from previous builds
            if self._shell_exec("git reset --hard", cwd=self.src_repo, build_step='build'):
                return
            if self._shell_exec("git checkout %s" % (refspec), cwd=self.src_repo, build_step='build'):
                return
            if self._shell_exec("git pull --commit --ff", cwd=self.src_repo, build_step='build'):
                return
            if self.build_row['revision'] == 'HEAD':
                commit_hash, stderr, exit_status = aegis.stdlib.shell('git rev-parse HEAD', cwd=self.src_repo)
                self.build_row.set_revision(commit_hash)
            # Generate new version number before cloning the new version tag into build directory
            self._new_version()
            env = {"GIT_COMMITTER_NAME": options.git_committer_name, "GIT_COMMITTER_EMAIL": options.git_committer_email,
                   "GIT_AUTHOR_NAME": options.git_committer_name, "GIT_AUTHOR_EMAIL": options.git_committer_email}
            if self._shell_exec("git tag %s" % self.next_tag, cwd=self.src_repo, build_step='build'):
                return
            if self._shell_exec("git push --tags", cwd=self.src_repo, build_step='build'):
                return
            self.build_row.set_version(self.next_tag)
            # Clone a fresh build into directory named by version tag
            app_dir = os.path.join(options.deploy_dir, options.program_name)
            self.build_dir = os.path.join(app_dir, self.next_tag)
            if os.path.exists(self.build_dir):
                if self._shell_exec("rm -rf %s" % build_dir, cwd=app_dir, build_step='build'):
                    return
            if self._shell_exec("git clone %s %s" % (self.src_repo, self.build_dir), cwd=app_dir, build_step='build'):
                return
            # write config files into the build directory and not version control
            version_file = os.path.join(self.build_dir, options.program_name, 'version.json')
            version_json = open(version_file, 'w')
            version_json.write('{"version": "%s"}\n' % self.next_tag)
            version_json.close()
            # Set up virtualenv
            if self._shell_exec("virtualenv --python=/usr/bin/python3 --system-site-packages virtualenv", cwd=self.build_dir, build_step='build'):
                return
            if self._shell_exec("virtualenv/bin/pip --cache-dir .cache install -e .", cwd=self.build_dir, build_step='build'):
                return
            # Set up and run yarn if it's installed
            self.yarn, stderr, exit_status = aegis.stdlib.shell('which yarn', cwd=self.src_dir)
            if self.yarn:
                if self._shell_exec("nice yarn install", cwd=self.build_dir, build_step='build'):
                    return
                if self._shell_exec("nice yarn run %s" % aegis.config.get('env'), cwd=self.build_dir, build_step='build'):
                    return
                build_file_version = self.next_tag
                if self.build_row['env'] in options.build_local_envs:
                    build_file_version = 'local'
                build_file_name = options.build_output_file % {'version': build_file_version}
                build_output_file = os.path.join(self.build_dir, build_file_name)
                if os.path.exists(build_output_file):
                    build_size = os.path.getsize(build_output_file)
                    if build_size:
                        self.build_row.set_build_size(build_size)
            # Rsync the files to the servers if it's configured
            rsync_hosts = [rh for rh in aegis.config.get('deploy_hosts') if rh != self.host]
            for rsync_host in rsync_hosts:
                cmd = "nice rsync -q --password-file=/etc/rsync.password -avzhW %s www-data@%s::%s" % (self.build_dir, rsync_host, options.rsync_module)
                if self._shell_exec(cmd, cwd=self.build_dir, build_step='build'):
                    return
        except Exception as ex:
            logging.exception(ex)
            self.build_row.set_output('build', "\n%s" % traceback.format_exc(), 1)
            return self._done_exec('build', 1)
        return self._done_exec('build', 0)


    def deploy(self, version, env, build_step='deploy', deploy_msg='', user=None):
        # Environment Settings
        deploy_build = aegis.model.Build.get_version(version)
        deploy_build = aegis.model.Build.get_id(deploy_build['build_id'])
        app_dir = os.path.join(options.deploy_dir, options.program_name)
        build_dir = os.path.join(app_dir, deploy_build['version'])
        live_symlink = os.path.join(app_dir, env)
        # Set self.build_row for where to record output if it's deploy, but don't overwrite in the revert case
        if build_step == 'deploy':
            self.build_row = deploy_build
        self.start_t = time.time()
        self.username, stderr, exit_status = aegis.stdlib.shell('whoami')
        self.host = socket.gethostname()
        # Set the previous version so we know what to revert back to, and mark it deployed, if this isn't happening to revert a build
        ## TODO notifications need to be moved into the clients, but it's attached to a lot
        if build_step == 'deploy':
            self.build_row = aegis.model.Build.get_id(self.build_row['build_id'])
            live_build = aegis.model.Build.get_live_build(self.build_row['env'])
            if live_build:
                self.build_row.set_previous_version(live_build['version'])
                self.build_row = aegis.model.Build.get_id(self.build_row['build_id'])
            self.build_row.set_deployed()
            # Send notifications
            commits, stderr, exit_status = aegis.stdlib.shell('git log --oneline --decorate %s..%s' % (self.build_row['previous_version'], self.build_row['version']), cwd=build_dir)
            commits = commits.splitlines()
            notification_body = "Release Notes by %s:  %s\n\n" % (user or os.getenv('SUDO_USER'), deploy_msg)
            notification_body += "Release Version: %s\n\n" % self.build_row['version']
            notification_body += "React Size: %s\n\n" % self.build_row['build_size']
            notification_body += "Release Commits:\n"
            for commit in commits:
                notification_body += "%s\n" % commit
            for channel in options.build_notification_channels:
                requests.post(channel, json={"text": notification_body})
        # What to restart
        processes, stderr, exit_status = aegis.stdlib.shell("sudo /usr/bin/supervisorctl status")
        processes = [process.split(' ')[0] for process in processes.splitlines() if process.split(':')[0].endswith('_'+env)]
        # Remove and re-link
        if self._shell_exec("rm -f %s" % live_symlink, build_step=build_step, cwd=app_dir):
            return
        if self._shell_exec("ln -s %s %s" % (build_dir, live_symlink), build_step=build_step, cwd=app_dir):
            return
        # Restart processes
        import __main__
        for process in processes:
            # Due to subprocess.Popen automatically receiving the SIGTERM from supervisor, we can't restart hydra from within supervisor.
            # https://stackoverflow.com/questions/52763508/python-prevent-child-threads-from-being-affected-from-sigint-signal
            # Instead, allow Hydra to use its quitting flag to stop and let supervisor restart.
            main_is_hydra = (__main__.__file__.endswith('hydra.py') or __main__.__file__.endswith('batch.py'))
            proc_is_hydra = (process.startswith('hydra') or process.startswith('batch'))
            if main_is_hydra and proc_is_hydra:
                logging.warning("Skip 'supervisorctl restart hydra' from within Hydra")
                continue
            # Restart processes one-by-one from supervisorctl
            if self._shell_exec("sudo /usr/bin/supervisorctl restart %s" % (process), build_step=build_step, cwd=app_dir):
                self.logw(process, "ERROR RESTARTING PROCESS")
                return
        return self._done_exec(build_step, 0)


    def revert(self, env, user=None):
        self.start_t = time.time()
        build_step = 'revert'
        self.build_row = aegis.model.Build.get_live_build(env)
        if not self.build_row:
            logging.error("There is currently no live build.")
            sys.exit(1)
        if not self.build_row['previous_version']:
            logging.error("Current live build doesn't have a previous_version to revert to.")
            return self._done_exec(build_step, 1)
        # Mark the build reverted, then run the deploy on the previous_version
        self.build_row.set_reverted()
        # Send notifications
        notification_body = "USER: %s  REVERT BUILD TO %s\n\n" % (user or os.getenv('SUDO_USER'), self.build_row['previous_version'])
        for channel in options.build_notification_channels:
            requests.post(channel, json={"text": notification_body})
        return self.deploy(self.build_row['previous_version'], env=env, build_step=build_step)


    # Shell execution with structured logging and database output handling.
    def _shell_exec(self, cmd, cwd, build_step, env=None):
        exec_output = "%s@%s:%s> %s" % (self.username, self.host, cwd, cmd)
        stdout, stderr, exit_status = aegis.stdlib.shell(cmd, cwd=cwd, env=env)
        if stdout:
            exec_output += '\n%s' % stdout
        if stderr:
            exec_output += "\n%s" % stderr
        exec_output += "\n"
        if exit_status:
            logging.error(exec_output.rstrip())
        else:
            logging.info(exec_output.rstrip())
        self.build_row.set_output(build_step, exec_output)
        self.build_row = aegis.model.Build.get_id(self.build_row['build_id'])
        if exit_status:
            self._done_exec(build_step, exit_status)
        return exit_status

    # Do the final summary writes after the build step is done.
    def _done_exec(self, build_step, exit_status):
        end_t = time.time()
        exec_t = end_t - self.start_t
        self.build_row.set_build_exec_sec(exec_t)
        exit_line = "\n  [ Exit %s   (%4.2f sec) ]\n" % (exit_status, exec_t)
        if exit_status:
            logging.error(exit_line.rstrip())
        else:
            logging.info(exit_line.rstrip())
        self.build_row.set_output(build_step, exit_line, exit_status)
        return exit_status


    # Version numbering and version files
    def _new_version(self):
        version_name = '%s_%s' % (self.build_row['env'], self.build_row['branch'])
        version_tags, stderr, exit_status = aegis.stdlib.shell("git tag --list '%s*'" % version_name, cwd=self.src_repo)
        if version_tags:
            for version_tag in sorted(version_tags.splitlines()):
                version_num = version_tag.rsplit('-')[-1]
                version_num = tuple([int(subversion) for subversion in version_num.split('.')])
        else:
            version_num = [0, 0, 0]
        x, y, z = version_num
        current_tag = '%s-%s.%s.%s' % (version_name, x, y, str(z).rjust(2, '0'))  # rjust to do z versions like .03 so they sort alphanumerically
        next_version = self._incr_version(*version_num)
        x, y, z = next_version
        self.next_tag = '%s-%s.%s.%s' % (version_name, x, y, str(z).rjust(2, '0'))


    # Increment minor (z) number up to 99 and the major numbers x and y to 10
    def _incr_version(self, x, y, z):
        if z < 99:
            return x, y, z+1
        z = 0
        if y < 9:
            return x, y+1, z
        y = 0
        return x+1, y, z
