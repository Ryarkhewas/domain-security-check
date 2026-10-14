"""Run the tool without installing it: python domain_check.py example.com

Once installed (pip install .), the "domain-security-check" command does the same.
"""

import sys

from domaincheck.cli import main

if __name__ == "__main__":
    sys.exit(main())
