"""Negative proof: actual desktop completes its protocol, wrapper exits 73."""
import subprocess
import sys

child = subprocess.Popen(sys.argv[1:])
code = child.wait()
raise SystemExit(73 if code == 0 else code)
