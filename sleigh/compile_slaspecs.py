#!/usr/bin/env python3
import glob
import sys
import subprocess
from pathlib import Path

assert len(sys.argv) == 2
slgh_bin_path = sys.argv[1]

for slaspec_file in glob.glob("./processors/**/*.slaspec", recursive=True):
    slaspec_file_path = Path(slaspec_file)
    sla_file_path = slaspec_file_path.with_suffix('.sla')
    subprocess.check_call([slgh_bin_path, slaspec_file_path, sla_file_path])
