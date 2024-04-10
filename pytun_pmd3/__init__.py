import sys

if sys.platform == 'win32':
    from pytun_pmd3.wintun import TunTapDevice
