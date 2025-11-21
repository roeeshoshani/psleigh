import pytest
from pysleigh import (
    BufMemReader,
    EmptyMemReader,
    Insn,
    LiftRes,
    MemReader,
    MemReaderDataUnavailErr,
    NoSuchRegErr,
    Opcode,
    Sleigh,
    SleighArch,
    Vn,
    VnAddr,
    VnSpace,
    VnSpaceInfo,
    VnSpaceKind,
)


def create_mem_reader(code_hex: str, addr: int = 0) -> BufMemReader:
    code = bytes.fromhex(code_hex)
    return BufMemReader(code, addr)


def test_basic_mips():
    # li $v0, 1
    reader = create_mem_reader("24 02 00 01")
    sleigh = Sleigh(SleighArch.mips32be(), reader)
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


def test_mips_partial_insn():
    # li $v0, 1
    # should be 24 02 00 01
    # removed the last byte
    reader = create_mem_reader("24 02 00")
    sleigh = Sleigh(SleighArch.mips32be(), reader)

    with pytest.raises(Exception):
        sleigh.lift_one(0)


def test_basic_x86_64():
    # mov rax, 0x1234567890abcdef
    reader = create_mem_reader("48 b8 ef cd ab 90 78 56 34 12")
    sleigh = Sleigh(SleighArch.x86_64(), reader)

    res = sleigh.lift_one(0)
    assert res == LiftRes(
        machine_insn_len=10,
        insns=[
            Insn(
                Opcode.COPY,
                [Vn(VnAddr(0x1234567890ABCDEF, VnSpace.const()), 8)],
                Vn(VnAddr(0, VnSpace.register()), 8),
            )
        ],
    )


def test_branch_x86_64():
    # jmp rip+0x10
    reader = create_mem_reader("eb 10", addr=0x1234)
    sleigh = Sleigh(SleighArch.x86_64(), reader)

    res = sleigh.lift_one(0x1234)
    assert res == LiftRes(
        machine_insn_len=2,
        insns=[
            Insn(
                Opcode.BRANCH,
                [Vn(VnAddr(0x1234 + 2 + 0x10, VnSpace.ram()), 8)],
                None,
            )
        ],
    )


def test_reader_error():
    ERR_MSG = "test reader error"

    class TestReaderErr(MemReader):
        def read(self, addr: int, amount: int) -> bytes:
            raise RuntimeError(ERR_MSG)

    sleigh = Sleigh(SleighArch.x86_64(), TestReaderErr())

    # Verify the exception propagates
    with pytest.raises(RuntimeError, match=ERR_MSG):
        sleigh.lift_one(0)


def test_reader_no_data():
    class TestReaderNoData(MemReader):
        def read(self, addr: int, amount: int) -> bytes:
            return b""

    sleigh = Sleigh(SleighArch.x86_64(), TestReaderNoData())

    with pytest.raises(Exception):
        sleigh.lift_one(0)


def test_basic_multiple_lift_calls():
    # mov rax, 0x1234567890abcdef
    # mov rax, 0
    reader = create_mem_reader("48 b8 ef cd ab 90 78 56 34 12 48 c7 c0 00 00 00 00")
    sleigh = Sleigh(SleighArch.x86_64(), reader)

    # first instruction
    res = sleigh.lift_one(0)
    assert res == LiftRes(
        machine_insn_len=10,
        insns=[
            Insn(
                Opcode.COPY,
                [Vn(VnAddr(0x1234567890ABCDEF, VnSpace.const()), 8)],
                Vn(VnAddr(0, VnSpace.register()), 8),
            )
        ],
    )

    # second instruction (at offset 10)
    res = sleigh.lift_one(10)
    assert res == LiftRes(
        machine_insn_len=7,
        insns=[
            Insn(
                Opcode.COPY,
                [Vn(VnAddr(0, VnSpace.const()), 8)],
                Vn(VnAddr(0, VnSpace.register()), 8),
            )
        ],
    )

    # re-lift the original addr
    res = sleigh.lift_one(0)
    assert res == LiftRes(
        machine_insn_len=10,
        insns=[
            Insn(
                Opcode.COPY,
                [Vn(VnAddr(0x1234567890ABCDEF, VnSpace.const()), 8)],
                Vn(VnAddr(0, VnSpace.register()), 8),
            )
        ],
    )


def test_space_info_mips():
    sleigh = Sleigh(SleighArch.mips32be(), EmptyMemReader())

    reg_space = sleigh.space_info(VnSpace.register())
    assert reg_space.shortcut == "%"
    assert reg_space.name == "register"
    assert reg_space.kind == VnSpaceKind.PROCESSOR

    const_space = sleigh.space_info(VnSpace.const())
    assert const_space.shortcut == "#"
    assert const_space.name == "const"
    assert const_space.kind == VnSpaceKind.CONSTANT

    ram_space = sleigh.space_info(VnSpace.ram())
    assert ram_space.shortcut == "r"
    assert ram_space.name == "ram"
    assert ram_space.kind == VnSpaceKind.PROCESSOR
    assert ram_space.word_size == 1
    assert ram_space.addr_size == 4


def test_space_info_x86_64():
    sleigh = Sleigh(SleighArch.x86_64(), EmptyMemReader())

    reg_space = sleigh.space_info(VnSpace.register())
    assert reg_space.shortcut == "%"
    assert reg_space.name == "register"
    assert reg_space.kind == VnSpaceKind.PROCESSOR

    const_space = sleigh.space_info(VnSpace.const())
    assert const_space.shortcut == "#"
    assert const_space.name == "const"
    assert const_space.kind == VnSpaceKind.CONSTANT

    ram_space = sleigh.space_info(VnSpace.ram())
    assert ram_space.shortcut == "r"
    assert ram_space.name == "ram"
    assert ram_space.kind == VnSpaceKind.PROCESSOR
    assert ram_space.word_size == 1
    assert ram_space.addr_size == 8


def test_reg_by_name_x86_64():
    sleigh = Sleigh(SleighArch.x86_64(), EmptyMemReader())

    regs = [
        "RAX",
        "RBX",
        "RCX",
        "RDX",
        "RSI",
        "RDI",
        "RSP",
        "RBP",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
    ]

    for reg_name in regs:
        reg = sleigh.reg_by_name(reg_name)
        assert reg.addr.space == VnSpace.register()
        assert reg.size == 8


def test_reg_by_name_mips():
    sleigh = Sleigh(SleighArch.mips32be(), EmptyMemReader())

    regs = [
        "zero",
        "at",
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "t6",
        "t7",
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "t8",
        "t9",
        "k0",
        "k1",
        "gp",
        "sp",
        "s8",
        "ra",
        "pc",
    ]

    for reg_name in regs:
        reg = sleigh.reg_by_name(reg_name)
        assert reg.addr.space == VnSpace.register()
        assert reg.size == 4


def test_reg_by_name_nonexistent():
    sleigh = Sleigh(SleighArch.mips32be(), EmptyMemReader())

    with pytest.raises(NoSuchRegErr):
        sleigh.reg_by_name("a22")


def test_reg_by_name_symbol_not_a_reg():
    sleigh = Sleigh(SleighArch.mips32be(), EmptyMemReader())

    # In the python bindings provided, `reg_by_name` raises NoSuchRegErr
    # if the underlying binding returns None.
    with pytest.raises(NoSuchRegErr):
        sleigh.reg_by_name("LowBitCodeMode")


def test_all_reg_names_x86_64():
    sleigh = Sleigh(SleighArch.x86_64(), EmptyMemReader())
    all_reg_names = sleigh.all_reg_names

    regs = [
        "RAX",
        "RBX",
        "RCX",
        "RDX",
        "RSI",
        "RDI",
        "RSP",
        "RBP",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
    ]

    for reg_name in regs:
        assert reg_name in all_reg_names


def test_all_reg_names_mips():
    sleigh = Sleigh(SleighArch.mips32be(), EmptyMemReader())
    all_reg_names = sleigh.all_reg_names

    regs = [
        "zero",
        "at",
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "t6",
        "t7",
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "t8",
        "t9",
        "k0",
        "k1",
        "gp",
        "sp",
        "s8",
        "ra",
        "pc",
    ]

    for reg_name in regs:
        assert reg_name in all_reg_names


def check_reg_to_name_generic(sleigh: Sleigh):
    all_reg_names = sleigh.all_reg_names
    for reg_name in all_reg_names:
        reg = sleigh.reg_by_name(reg_name)
        assert sleigh.reg_to_name(reg) == reg_name


def test_reg_to_name_x86_64():
    sleigh = Sleigh(SleighArch.x86_64(), EmptyMemReader())
    check_reg_to_name_generic(sleigh)


def test_reg_to_name_mips():
    sleigh = Sleigh(SleighArch.mips32be(), EmptyMemReader())
    check_reg_to_name_generic(sleigh)


def test_reg_to_name_unnamed_reg():
    sleigh = Sleigh(SleighArch.x86_64(), EmptyMemReader())

    # construct the register one byte after ah, it has no name
    ah = sleigh.reg_by_name("AH")
    ah_plus_one = Vn(VnAddr(ah.addr.off + 1, ah.addr.space), ah.size)

    assert sleigh.reg_to_name(ah_plus_one) is None

