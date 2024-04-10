import sys

if sys.platform == 'win32':
    from pytun_pmd3.wintun import TunTapDevice
else:
    from pytun_pmd3_c import TunTapDevice
