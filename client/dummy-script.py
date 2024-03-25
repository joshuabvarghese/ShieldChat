# Docker dummy script to run on boot up

import os, stat

# Add execute permission on client.py
os.chmod("./client.py", stat.S_IXUSR)

while True:
    pass
