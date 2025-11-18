from .pysleigh_bindings import Sleigh, SimpleLoadImage

class MyLoadImage(SimpleLoadImage):
    def loadSimple(addr, amount):
        return b'\x00'*amount

s = Sleigh(b'hello', MyLoadImage())
