#!/usr/bin/env python3

__author__ = "Andrea Fioraldi"
__copyright__ = "Copyright 2019, Andrea Fioraldi"
__license__ = "BSD 2-Clause"
__email__ = "andreafioraldi@gmail.com"

from setuptools import setup

VER = "1.0.0"

setup(
    name='deferred_driller',
    version=VER,
    license=__license__,
    description='My version of driller using Intel PIN and angrgdb. In "theory" can work with AFL in deferred and persistent mode.',
    author=__author__,
    author_email=__email__,
    url='https://github.com/andreafioraldi/deferred_driller',
    download_url = 'https://github.com/andreafioraldi/deferred_driller/archive/' + VER + '.tar.gz',
    package_dir={'deferred_driller': 'deferred_driller'},
    packages=['deferred_driller'],
    install_requires=[
        'angrgdb'
    ],
)
