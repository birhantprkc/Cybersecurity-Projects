"""
©AngelaMos | 2026
schemas.py
"""

from pydantic import BaseModel

from rveng.api.limits import DEFAULT_SESSION, MAX_ANSWER_LEN


class ChallengeSummary(BaseModel):
    id: str
    module: str
    title: str


class ChallengeDetail(BaseModel):
    id: str
    module: str
    title: str
    mission: str
    category: str
    size: int


class HexView(BaseModel):
    base: int
    length: int
    lines: list[str]


class FunctionView(BaseModel):
    name: str
    value: int
    size: int


class SectionView(BaseModel):
    index: int
    name: str
    type: str
    addr: int
    offset: int
    size: int
    flags: str


class ElfView(BaseModel):
    type: int
    machine: int
    entry: int
    sections: list[SectionView]
    functions: list[FunctionView]


class InstructionView(BaseModel):
    address: int
    mnemonic: str
    op_str: str
    bytes: str
    immediate: int | None
    branch_target: int | None
    is_gate: bool


class DisasmView(BaseModel):
    symbol: str
    instructions: list[InstructionView]
    gate_address: int | None


class StringView(BaseModel):
    offset: int
    text: str


class StringsView(BaseModel):
    strings: list[StringView]


class SubmitRequest(BaseModel):
    answer: str
    session: str = DEFAULT_SESSION

    def within_limits(self) -> bool:
        return len(self.answer) <= MAX_ANSWER_LEN


class SubmitResult(BaseModel):
    correct: bool
    message: str
    revealed_source: str | None


class ProgressView(BaseModel):
    session: str
    solved: list[str]
    total: int
