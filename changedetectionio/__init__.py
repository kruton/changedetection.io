#!/usr/bin/env python3

# Read more https://github.com/dgtlmoon/changedetection.io/wiki

import enum

__version__ = '0.46.02'


class Sentinel(enum.Enum):
    """Used to indicate the end of a queue."""
    TOKEN = 0
