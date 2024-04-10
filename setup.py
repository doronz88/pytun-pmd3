import sys
from pathlib import Path

from setuptools import Extension, find_packages, setup

if sys.platform in ['darwin', 'linux']:
    if sys.platform == 'darwin':
        sources = ['darwin_pytun.c']
    else:
        sources = ['linux_pytun.c']

    setup(name='pytun-pmd3', ext_modules=[
        Extension('pytun_pmd3_c', sources, include_dirs=[Path(__file__).parent])],
          extra_compile_args=["-Wall", "-Wextra", "-pedantic"])
else:
    # windows
    setup(name='pytun-pmd3', packages=find_packages())
