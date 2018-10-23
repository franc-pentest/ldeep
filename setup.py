#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import codecs
from setuptools import setup, find_packages
import sys

dirname = os.path.dirname(__file__)
version = open(os.path.join(dirname, "VERSION")).read().strip()
requirements = [line[:-1] for line in open(os.path.join(dirname, "requirements.txt"), "r").readlines()]

setup(
	# Basic info
	name="ldeep",
	version=version,
	author="b0z, flgy",
	author_email="bastien@faure.io, florian.guilbert@synacktiv.com",
	keywords='pentesting security windows active-directory networks',
	url="https://github.com/franc-pentest/ldeep",
	license="MIT",
	description="In-depth ldap enumeration utility",
	long_description=codecs.open("README.rst", "rb", "utf8").read(),

	# Classifiers (see https://pypi.python.org/pypi?%3Aaction=list_classifiers)
	classifiers=[
		"Development Status :: 4 - Beta",
		"Intended Audience :: Information Technology",
		"License :: OSI Approved :: MIT License",
		"Programming Language :: Python",
		"Programming Language :: Python :: 3.3",
		"Programming Language :: Python :: 3 :: Only",
		"Topic :: Security",
		"Operating System :: OS Independent",
	],

	# Packages and dependencies
	#package_dir={"": "ldeep"},
	packages=find_packages(include=["ldeep", "ldeep.*"]),
	install_requires=requirements,

	# Other configurations
	zip_safe=True,
	platforms='any',
	# entry points
	entry_points={
		"console_scripts": [
			"ldeep = ldeep.__main__:main"
		]
	},
	python_requires=">=3.3"
)
