#!/usr/bin/env python3

"""
Build {{app_name}} inside of a virtualenv.
virtualenv --python=`which python3` --distribute --system-site-packages virtualenv
"""

import os
import setuptools

setuptools.setup (
    name = '{{app_name}}',
    version = '0.0',
    description = '{{app_name}}',
    author = "",
    author_email = '',
    url = '',
    install_requires = [
        'tornado == 4.5.2',
        'psycopg2 == 2.7.3.2',
        'aegis == 0.0.1',
    ],
    dependency_links=['https://bitbucket.org/mdagosta/aegis/get/rough-draft.tar.gz'],
    package_data = { '': ['templates/*', 'static/*/*', 'sql/*'] },
)
