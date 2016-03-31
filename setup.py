#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    # TODO: put package requirements here
]

test_requirements = [
    'pytest'
]

setup(
    name='desfire',
    version='0.2',
    description="MIFARE DESFire NFC card communication protocol",
    long_description=readme + '\n\n' + history,
    author="Mikko Ohtamaa",
    author_email='mikko@opensourcehacker.com',
    url='https://github.com/miohtama/desfire',
    packages=[
        'desfire',
    ],
    package_dir={'desfire':
                 'desfire'},
    include_package_data=True,
    install_requires=requirements,
    license="BSD",
    zip_safe=False,
    keywords='desfire nfc mifare 14443',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    setup_requires=["pytest-runner"],
    tests_require=test_requirements
)
