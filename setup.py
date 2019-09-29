#!/usr/bin/env python3

"""
Minimal packaging setup to use command line tools to get started
virtualenv --python=`which python3` virtualenv
. ./virtualenv/bin/activate
python setup.py develop
"""

import os
import setuptools

setuptools.setup (
    name = 'aegis',
    version = '0.0.1',
    description = 'Aegis is a set of battle-tested tools and tricks to help everyone make better software',
    author = "Michael D'Agosta",
    author_email = 'mdagosta@codebug.com',
    url = 'https://bitbucket.org/mdagosta/aegis',
    packages = ['aegis'],
    #entry_points={
    #    'console_scripts': [
    #        'rst2pdf = project_a.tools.pdfgen [PDF]',
    #        'rst2html = project_a.tools.htmlgen',
    #        # more script entry points ...
    #    ],
    #}
)
