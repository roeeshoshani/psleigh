from pysleigh import (
    BufMemReader,
    Insn,
    LiftRes,
    Opcode,
    Sleigh,
    SleighArch,
    Vn,
    VnAddr,
    VnSpace,
)


def test_basic_mips():
    # li $v0, 1
    code = bytes.fromhex("24 02 00 01")
    sleigh = Sleigh(SleighArch.mips32be(), BufMemReader(code, 0))
    res = sleigh.lift_one(0)
    assert res == LiftRes(
        machine_insn_len=4,
        insns=[
            Insn(
                Opcode.COPY,
                [Vn(VnAddr(1, VnSpace.const()), 4)],
                Vn(VnAddr(8, VnSpace.register()), 4),
            )
        ],
    )
