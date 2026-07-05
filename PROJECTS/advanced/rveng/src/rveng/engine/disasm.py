"""
©AngelaMos | 2026
disasm.py
"""

from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL, Cs
from capstone.x86 import X86_OP_IMM

from rveng.engine.elf import ElfImage, Symbol

COMPARE_MNEMONICS = frozenset({"cmp", "test"})
CONDITIONAL_JUMPS = frozenset({
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno",
    "jp", "jnp", "jc", "jnc",
})
CALL_JUMP = frozenset({"call", "jmp"})


@dataclass(frozen=True)
class Instruction:
    """
    One decoded x86-64 instruction with teaching annotation
    """

    address: int
    mnemonic: str
    op_str: str
    raw: bytes
    immediate: int | None
    branch_target: int | None = None

    @property
    def size(self) -> int:
        return len(self.raw)

    @property
    def is_compare(self) -> bool:
        return self.mnemonic in COMPARE_MNEMONICS

    @property
    def is_conditional_branch(self) -> bool:
        return self.mnemonic in CONDITIONAL_JUMPS

    @property
    def is_flow(self) -> bool:
        return (self.mnemonic in CONDITIONAL_JUMPS
                or self.mnemonic in CALL_JUMP)

    def render(self) -> str:
        return f"{self.address:x}: {self.mnemonic} {self.op_str}".rstrip()


def _new_engine() -> Cs:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.syntax = CS_OPT_SYNTAX_INTEL
    md.detail = True
    return md


def _immediate(ins) -> int | None:
    value = None
    for operand in ins.operands:
        if operand.type == X86_OP_IMM:
            value = operand.imm
    return value


def disassemble(code: bytes, base: int = 0) -> list[Instruction]:
    """
    Decode a byte range into annotated instructions at virtual base
    """
    md = _new_engine()
    out = []
    for ins in md.disasm(code, base):
        imm = _immediate(ins)
        flow = (ins.mnemonic in CONDITIONAL_JUMPS
                or ins.mnemonic in CALL_JUMP)
        out.append(Instruction(
            address=ins.address,
            mnemonic=ins.mnemonic,
            op_str=ins.op_str,
            raw=bytes(ins.bytes),
            immediate=None if flow else imm,
            branch_target=imm if flow else None,
        ))
    return out


def disassemble_symbol(
        image: ElfImage, symbol: Symbol) -> list[Instruction]:
    """
    Disassemble one function symbol from its owning in-file section
    """
    shndx = symbol.shndx
    if shndx <= 0 or shndx >= len(image.sections):
        raise ValueError("symbol is not defined in an in-file section")
    section = image.sections[shndx]
    start = symbol.value - section.addr + section.offset
    if start < 0 or start + symbol.size > len(image.data):
        raise ValueError("symbol maps outside the file")
    code = image.data[start:start + symbol.size]
    return disassemble(code, symbol.value)


def find_gate(instructions: list[Instruction]) -> Instruction | None:
    """
    Return the first comparison instruction that carries an immediate
    """
    for ins in instructions:
        if ins.is_compare and ins.immediate is not None:
            return ins
    return None
