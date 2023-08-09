import sys

from setuptools import setup, Extension

if sys.platform == 'darwin':
    sources = ['darwin_pytun.c']
else:
    sources = ['linux_pytun.c']

setup(name='pytun-pmd3',
      author='doronz88',
      author_email='doron88@gmail.com',
      maintainer='doronz88',
      maintainer_email='doron88@gmail.com',
      url='https://github.com/doronz88/pytun-pmd3',
      description='Linux & Darwin TUN/TAP wrapper for Python',
      long_description=open('README.rst').read(),
      version='0.0.1',
      ext_modules=[Extension('pytun_pmd3', sources)],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: POSIX :: Linux',
          'Operating System :: MacOS',
          'Programming Language :: C',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking'])
