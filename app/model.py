"""领域模型：规程、节点、审计结果。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 节点类型
JUMP = "jump"          # 普通跳转
CALL = "call"          # 调用目标入口并指定返回续点
RETURN = "return"      # 正常返回
DANGER = "danger"      # 危险节点（汇聚点；无后继）

VALID_TYPES = (JUMP, CALL, RETURN, DANGER)

# 规程数量上限
MAX_PROCEDURES = 12


@dataclass
class Node:
    nid: str
    ntype: str
    target: str | None = None     # call: 被调用规程入口；jump: 下一节点
    cont: str | None = None       # call: 返回续点
    proc: str = ""                # 所属规程标识（校验时填充）


@dataclass
class Procedure:
    pid: str
    entry: str
    nodes: dict[str, Node] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {"id": self.pid, "entry": self.entry,
                "nodes": [n for n in self.nodes.values()]}


@dataclass
class Step:
    """链路上的一步（执行一个节点）及其执行后的调用栈。"""
    index: int
    node_id: str
    proc: str
    kind: str
    target: str | None
    cont: str | None
    dangerous: bool
    stack: list[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "node": self.node_id,
            "procedure": self.proc,
            "kind": self.kind,
            "target": self.target,
            "cont": self.cont,
            "dangerous": self.dangerous,
            "stack": list(self.stack),
        }


@dataclass
class AuditResult:
    audit_id: str
    root_entry: str
    dangerous_reachable: bool
    steps: list[Step]
    final_stack: list[str]
    summary: dict[str, Any]
    frozen_payload: dict[str, Any]
    conclusion: str
