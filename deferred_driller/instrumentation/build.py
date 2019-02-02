#!/usr/bin/env python3

import glob
import os

pin_path = glob.glob('./pin-*')
assert len(pin_path) == 1
pin_path = pin_path[0]

os.system("make PIN_ROOT=%s" % pin_path)
