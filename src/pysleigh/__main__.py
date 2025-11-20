from __future__ import annotations
from .pysleigh_bindings import (
    BindingsSleigh,
    BindingsSimpleLoadImage,
    BindingsLiftRes,
    BindingsInsn,
    BindingsVarnodeData,
    BindingsAddrSpace,
)
from pathlib import Path
from abc import ABC, ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Self

PROCESSORS_DIR = Path(__file__).parent.joinpath("processors")


class MemReaderMeta(type(BindingsSimpleLoadImage), ABCMeta):
    pass


class MemReader(ABC, BindingsSimpleLoadImage, metaclass=MemReaderMeta):
    @abstractmethod
    def read(self, addr: int, amount: int) -> bytes:
        pass

    def loadSimple(self, addr: int, amount: int) -> bytes:
        return self.read(addr, amount)


class MyLoadImage(MemReader):
    def read(self, addr: int, amount: int) -> bytes:
        return b"\x00" * amount


SLA_RELATIVE_PATH_X86_64 = "x86/data/languages/x86-64.sla"


@dataclass
class VnSpace:
    shortcut: str

    @classmethod
    def from_bindings(cls, bindings_addr_space: BindingsAddrSpace) -> Self:
        return cls(bindings_addr_space.getShortcut())


@dataclass
class VnAddr:
    off: int
    space: VnSpace


@dataclass
class Vn:
    addr: VnAddr
    size: int

    @classmethod
    def from_bindings(cls, bindings_vn: BindingsVarnodeData) -> Self:
        addr = VnAddr(
            bindings_vn.getOffset(), VnSpace.from_bindings(bindings_vn.getSpace())
        )
        return cls(addr, bindings_vn.getSize())


@dataclass
class Insn:
    opcode: int
    inputs: List[Vn]
    output: Optional[Vn]

    @classmethod
    def from_bindings(cls, bindings_insn: BindingsInsn) -> Self:
        bindings_opcode = bindings_insn.opcode()

        inputs_amount = bindings_insn.inVarsAmount()
        inputs = [
            Vn.from_bindings(bindings_insn.inVar(i)) for i in range(inputs_amount)
        ]

        bindings_output: Optional[BindingsVarnodeData] = bindings_insn.outVar()
        output = (
            Vn.from_bindings(bindings_output) if bindings_output is not None else None
        )

        return cls(bindings_opcode, inputs, output)


@dataclass
class LiftRes:
    machine_insn_len: int
    insns: List[Insn]

    @classmethod
    def from_bindings(cls, bindings_lift_res: BindingsLiftRes) -> Self:
        machine_insn_len = bindings_lift_res.machineInsnLen()

        insns_amount = bindings_lift_res.insnsAmount()
        insns = [
            Insn.from_bindings(bindings_lift_res.insn(i)) for i in range(insns_amount)
        ]

        return cls(machine_insn_len, insns)


class Sleigh:
    def __init__(self, sla_relative_path: str):
        sla_path = PROCESSORS_DIR.joinpath(sla_relative_path)
        self.bindings_sleigh = BindingsSleigh(str(sla_path), MyLoadImage())

    def lift_one(self, addr: int) -> LiftRes:
        bindings_lift_res = self.bindings_sleigh.liftOne(addr)
        return LiftRes.from_bindings(bindings_lift_res)


sleigh = Sleigh(SLA_RELATIVE_PATH_X86_64)
res = sleigh.lift_one(0)
print(res)
