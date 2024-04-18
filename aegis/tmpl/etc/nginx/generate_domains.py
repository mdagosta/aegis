#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Generate Domain
#
# Create epiphyte-specific domain files for nginx directly into sites-enabled

import logging
import os
import sys

import aegis.stdlib


# Configuring on a per-user per-domain basis
domains = {'dashboard.birthdayalarm.com': {'envs': ['md', 'nick', 'dev', 'prod']}}

envs = {'md': {'src_dir': '/home/mdagosta/src/bday-dashboard'},
        'nick': {'src_dir': '/home/nick/src/bday-dashboard'},
        'dev': {'src_dir': '/srv/www/bday-dashboard_dev'},
        'prod': {'src_dir': '/srv/www/bday-dashboard/prod', 'etc_dir': ''}
        }


# One standard nginx server to rule them all
template = """# {{env}} environment
server {
    listen         80;
    server_name    {{server_name}};
    server_tokens  off;
    return         301 https://{{hostname}}$request_uri;
    access_log     /var/log/nginx/epiphyte-{{env}}.access.log epiphyte;
    error_log      /var/log/nginx/epiphyte-{{env}}.error.log;
}

server {
    listen 443 ssl;
    server_name {{server_name}};
    server_tokens off;
    access_log /var/log/nginx/epiphyte-{{env}}.access-ssl.log epiphyte;
    error_log /var/log/nginx/epiphyte-{{env}}.error-ssl.log;

    set $app_root {{src_dir}}/epiphyte;
    set $host_root {{src_dir}}/epiphyte/sites/$host;
    root $host_root/;

    ssl_certificate {{etc_dir}}/etc/nginx/ssl/star.{{domain}}.CF-origin.crt;
    ssl_certificate_key {{etc_dir}}/etc/nginx/ssl/star.{{domain}}.CF-origin.key;

    # HTTP Basic Auth
    auth_basic "Get Your Own";
    auth_basic_user_file {{etc_dir}}/etc/nginx/http_basic_auth;

    # Sink annoying probing requests to HTTP 410 Gone without logging
    include {{etc_dir}}/etc/nginx/sink_gone.conf;

    # Use standardized error pages to send a decent error mode to the client
    include {{etc_dir}}/etc/nginx/error_pages.conf;

    # Configure real_ip_header from Cloudflare
    include {{etc_dir}}/etc/nginx/cloudflare.conf;

    # Baseline Secure Headers
    add_header Strict-Transport-Security max-age=63072000 always;
    add_header X-Content-Type-Options nosniff always;
    add_header Permissions-Policy microphone=(),camera=(),display-capture=(),geolocation=() always;
    #add_header Allow "GET, POST" always;
    if ( $request_method !~ ^(GET|POST)$ ) { return 405; }

    # Application
    location /apple-touch-icon.png { expires 8d; }
    location /favicon.ico { expires 8d; }
    location /robots.txt { expires 1d; root $app_root;try_files /sites/$host/static/robots.txt /static/robots.txt =404; }
    location /sitemap.xml { expires 1d; }
    location ~ /static/(.*) {
      root $app_root;
      expires 8d;   # not in if because If is evil: https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/
      try_files /sites/$host/static/$1 /static/$1 =404;
    }
    location /admin/build { proxy_pass http://{{env}}-admin_epiphyte_tornados; proxy_next_upstream off; }
    location / { proxy_pass http://{{env}}_epiphyte_tornados; }
}



"""




# Building nginx site config and writing to filesystem
dirname = os.path.abspath(os.path.dirname(__file__))
sites_enabled = os.path.join(dirname, 'sites-enabled')

# iterate through the domains, then build a template for each env in that domain
for domain, domain_envs in domains.items():
    rendered = ''
    # iterate the envs
    for env in domain_envs['envs']:
        configs = envs[env]
        configs['env'] = env
        configs['domain'] = domain
        # Generate server_name and hostname from env and domain
        env_name = env
        if env_name == 'prod':
            env_name = ''
        configs['server_name'] = '%s.%s' % (env_name, domain)
        configs['hostname'] = ('%s.%s' % (env_name, domain)).strip('.')
        # Generate etc_dir if not prod
        if 'etc_dir' not in configs:
            configs['etc_dir'] = '%s' % configs['src_dir']
        # Render template with replaced params
        host = template
        for config, value in configs.items():
            host = host.replace('{{%s}}' % config, configs[config])
        host_render = []
        # Filter out auth_basic in production
        auth_filter = None
        if configs['env'] == 'prod':
            auth_filter = 'auth_basic'
        lines = host.splitlines()
        lines = [ line for line in lines if not auth_filter or auth_filter not in line ]
        # Filter out admin in non-deployed admin
        admin_filter = None
        if configs['env'] in ['md', 'nick']:
            admin_filter = '/admin/build'
        lines = [ line for line in lines if not admin_filter or admin_filter not in line ]
        host_render = lines
        rendered += '\n'.join(host_render)
    filename = os.path.join(sites_enabled, domain + '.conf')
    with open(filename, 'w') as fd:
        fd.write(rendered)
print ("GREAT SUCCESS!!")
