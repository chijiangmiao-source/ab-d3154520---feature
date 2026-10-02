"""审计证据与处置方案存储：冻结结论、按标识读取、载荷一致性。"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict
from typing import Any

from .analyzer import Analyzer
from .mincost import CostSolver
from .model import AuditResult, DisposalResult, Procedure
from .validate import parse_and_validate, parse_and_validate_disposal


def canonical_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _freeze_payload(procedures: list, audit_id: str, root_entry: str) -> dict:
    return {
        "audit_id": audit_id,
        "root_entry": root_entry,
        "procedures": [
            {
                "id": p.pid,
                "entry": p.entry,
                "nodes": [
                    {k: v for k, v in {
                        "id": n.nid, "type": n.ntype,
                        "next": n.target if n.ntype == "jump" else None,
                        "target": n.target if n.ntype == "call" else None,
                        "cont": n.cont if n.ntype == "call" else None,
                    }.items() if v is not None}
                    for n in p.nodes.values()
                ],
            }
            for p in procedures
        ],
    }


class Store:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, dict[str, Any]] = {}
        self._disposals: dict[str, dict[str, Any]] = {}

    def analyze(
        self, payload: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, list[str] | None, str | None]:
        """返回 (result_json, validation_errors, conflict_message)。"""
        audit_id, root_entry, procedures = parse_and_validate(payload)
        fp = canonical_hash(_freeze_payload(procedures, audit_id, root_entry))

        with self._lock:
            existing = self._by_id.get(audit_id)
            if existing is not None:
                if existing["fingerprint"] == fp:
                    result = dict(existing["result"])
                    result["replayed"] = True  # 同标识同载荷：回放冻结结论
                    return result, None, None
                # 同标识不同载荷：明确拒绝
                return None, None, (
                    f"审计标识 {audit_id} 已冻结于不同载荷，"
                    "改换载荷被拒绝；请使用新的稳定审计标识"
                )

            analyzer = Analyzer(procedures)
            dangerous = analyzer.root_dangerous(root_proc=root_entry)
            steps = analyzer.replay(root_entry) if dangerous else []
            frozen = _freeze_payload(procedures, audit_id, root_entry)
            result = AuditResult(
                audit_id=audit_id,
                root_entry=root_entry,
                dangerous_reachable=dangerous,
                steps=steps,
                final_stack=steps[-1].stack if steps else [
                    f"{root_entry}.{next(p.entry for p in procedures if p.pid == root_entry)}"
                ],
                summary=analyzer.summary(root_entry),
                frozen_payload=frozen,
                conclusion=(
                    f"危险节点可从根入口 {root_entry} 抵达（见逐步调用栈链）"
                    if dangerous else
                    f"安全：危险节点无法从根入口 {root_entry} 抵达"
                ),
            )
            record = {
                "fingerprint": fp,
                "result": asdict(result),
                "procedures": procedures,  # 仅供后续处置求解，不序列化
            }
            self._by_id[audit_id] = record
            out = dict(record["result"])
            out["replayed"] = False
            return out, None, None

    def get(self, audit_id: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._by_id.get(audit_id)
            return rec["result"] if rec else None

    # ---------- 处置方案 ----------
    def _source_of(self, audit_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._by_id.get(audit_id)

    def dispose(
        self, payload: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str | None]:
        """返回 (result_json, conflict_message)。

        校验失败抛 PayloadError，来源不存在抛 SourceMissing；任何拒绝都
        不改写原审计与已冻结方案。
        """
        disposal_id, audit_id, costs, source = parse_and_validate_disposal(
            payload, self._source_of
        )
        frozen = {
            "disposal_id": disposal_id,
            "audit_id": audit_id,
            "costs": [{"node": nid, "cost": costs[nid]} for nid in sorted(costs)],
        }
        fp = canonical_hash(frozen)

        with self._lock:
            existing = self._disposals.get(disposal_id)
            if existing is not None:
                if existing["fingerprint"] == fp:
                    result = dict(existing["result"])
                    result["replayed"] = True  # 同标识同载荷：回放冻结方案
                    return result, None
                # 同标识改换来源或代价表：明确拒绝
                return None, (
                    f"处置标识 {disposal_id} 已冻结于不同来源或代价表，"
                    "改换被拒绝；请使用新的稳定处置标识"
                )

            procedures = source["procedures"]
            root_entry = source["result"]["root_entry"]
            solver = CostSolver(procedures, costs)
            best = solver.min_cost(root_entry)
            steps = solver.replay(root_entry)
            if best is None or not steps:
                raise RuntimeError("来源审计危险可达但代价求解为空（不应发生）")
            danger_node = f"{steps[-1].proc}.{steps[-1].node_id}"
            result = DisposalResult(
                disposal_id=disposal_id,
                audit_id=audit_id,
                min_cost=int(best[0]),
                events=int(best[1]),
                danger_node=danger_node,
                steps=steps,
                final_stack=steps[-1].stack,
                frozen_payload=frozen,
                conclusion=(
                    f"抵达同一危险节点 {danger_node} 的最低总代价为 "
                    f"{int(best[0])}（{int(best[1])} 个事件，"
                    "逐步链含累计代价与调用栈）"
                ),
            )
            record = {"fingerprint": fp, "result": asdict(result)}
            self._disposals[disposal_id] = record
            out = dict(record["result"])
            out["replayed"] = False
            return out, None

    def get_disposal(self, disposal_id: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._disposals.get(disposal_id)
            return rec["result"] if rec else None
