import sys

from setuptools import setup, Extension

if sys.platform == 'darwin':
    sources = ['darwin_pytun.c']
else:
    sources = ['linux_pytun.c']

setup(name='pytun-pmd3', ext_modules=[Extension('pytun_pmd3', sources, include_dirs=['.'])])
