#!/usr/bin/env python
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.cli.admin_init import initialize_admin

if __name__ == "__main__":
    initialize_admin()
