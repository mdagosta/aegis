#!/usr/bin/env python3

"""
Minimal packaging setup to use command line tools to get started after checking out the repository:
virtualenv --python=`which python3` virtualenv
. ./virtualenv/bin/activate
python setup.py develop

To build aegis for PyPi:

Increment the version # ... should this be tied to git tag? `aegis release` ?
rm dist/*
python3 setup.py sdist bdist_wheel
python3 -m twine upload dist/*
"""

import os
import setuptools

setuptools.setup (
    name = 'aegis-tools',
    version = '0.6.8',
    description = 'Aegis is a set of battle-tested tools and tricks to help everyone make better software',
    long_description = 'A combination of tools and framework, Aegis has multiple different uses. You can import it and use the thoroughly made and tested functions. You can use it as a natural extension for the tornado web framework. And you can use it to quickly create a new web application with the structure already built-in, and follow along.',
    author = "Michael D'Agosta",
    author_email = 'mdagosta@codebug.com',
    url = 'https://bitbucket.org/mdagosta/aegis',
    python_requires='>=3.6',
    packages = ['aegis'],
    package_data = {'aegis': ['templates/*', 'sql/*']},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        'console_scripts': [
            "aegis = aegis.aegis_:main",
        ],
    },
    install_requires = [
        'python-dateutil',
        'requests',
        'tornado == 4.5.2',
        'user_agents',
    ]
)
