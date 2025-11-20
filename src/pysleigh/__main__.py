from .pysleigh_bindings import Sleigh, SimpleLoadImage
from pathlib import Path

class MyLoadImage(SimpleLoadImage):
    def loadSimple(addr, amount):
        return b'\x00'*amount

PROCESSORS_DIR = Path(__file__).parent.joinpath('processors')
sla_path = PROCESSORS_DIR.joinpath('x86/data/languages/x86-64.sla')
sla_path_str = str(sla_path)
s = Sleigh(sla_path_str, MyLoadImage())
