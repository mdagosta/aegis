#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Generate Domain
#
# Create {{app_name}}-specific domain files for nginx directly into sites-enabled

import logging
import os
import sys

domains = ['{{aegis_domain}}']
dev_envs = {'dev': '/srv/www/{{app_name}}_dev'}

dev_template = """### {{dev_env}}
server {
    listen         80;
    server_name    {{dev_env}}.{{domain}};
    return         301 https://{{dev_env}}.{{domain}}$request_uri;
    access_log     /var/log/nginx/{{app_name}}-{{dev_env}}.access.log {{app_name}};
    error_log      /var/log/nginx/{{app_name}}-{{dev_env}}.error.log;
}


server {
    listen 443 ssl;
    server_name {{dev_env}}.{{domain}};
    access_log /var/log/nginx/{{app_name}}-{{dev_env}}.access-ssl.log {{app_name}};
    error_log /var/log/nginx/{{app_name}}-{{dev_env}}.error-ssl.log;
    set $app_root {{src_dir}}/{{app_name}};
    root $app_root/;

    ssl on;
    ssl_certificate /etc/nginx/ssl/star.{{domain}}.CF-origin.crt;
    ssl_certificate_key /etc/nginx/ssl/star.{{domain}}.CF-origin.key;

    auth_basic "Regnu {{app_name}}";
    auth_basic_user_file /etc/nginx/http_basic_auth;

    # Sink annoying probing requests to HTTP 410 Gone without logging
    include {{src_dir}}/etc/nginx/sink_gone.conf;

    # Use standardized error pages to send a decent error mode to the client
    include {{src_dir}}/etc/nginx/error_pages.conf;

    # Configure real_ip_header from Cloudflare
    include {{src_dir}}/etc/nginx/cloudflare.conf;

    # Application
    location /favicon.ico { root $app_root/sites/$host; }
    location /robots.txt { root $app_root/sites/$host; }
    location /sitemap.xml { root $app_root/sites/$host; }
    location /static { if ($query_string) { expires 8d; } }
    location / { proxy_pass http://{{dev_env}}_{{app_name}}_tornados; }
}

"""

prod_template = """### prod
server {
    listen         80;
    server_name    .{{domain}};
    return         301 https://{{domain}}$request_uri;
    access_log     /var/log/nginx/{{app_name}}-prod.access.log {{app_name}};
    error_log      /var/log/nginx/{{app_name}}-prod.error.log;
}


server {
    listen 443 ssl;
    server_name .{{domain}};
    access_log /var/log/nginx/{{app_name}}-prod.access-ssl.log {{app_name}};
    error_log /var/log/nginx/{{app_name}}-prod.error-ssl.log;
    set $app_root /srv/www/{{app_name}}_prod/{{app_name}};
    root $app_root/;

    ssl on;
    ssl_certificate /etc/nginx/ssl/star.{{domain}}.CF-origin.crt;
    ssl_certificate_key /etc/nginx/ssl/star.{{domain}}.CF-origin.key;

    # Sink annoying probing requests to HTTP 410 Gone without logging
    include /etc/nginx/sink_gone.conf;

    # Use standardized error pages to send a decent error mode to the client
    include /etc/nginx/error_pages.conf;

    # Configure real_ip_header from Cloudflare
    include /etc/nginx/cloudflare.conf;

    # Application
    location /favicon.ico { root $app_root/sites/$host; }
    location /robots.txt { root $app_root/sites/$host; }
    location /sitemap.xml { root $app_root/sites/$host; }
    location /static { if ($query_string) { expires 8d; } }
    location / { proxy_pass http://prod_{{app_name}}_tornados; }
}"""

template = ''
for dev_env, src_dir in dev_envs.items():
    template += dev_template.replace('{{dev_env}}', dev_env).replace('{{src_dir}}', src_dir)
template += prod_template

dirname = os.path.abspath(os.path.dirname(__file__))
sites_enabled = os.path.join(dirname, 'sites-enabled')
for domain in domains:
    filename = os.path.join(sites_enabled, domain + '.conf')
    with open(filename, 'w') as fd:
        fd.write(template.replace('{{domain}}', domain))
print ("GREAT SUCCESS!!")
