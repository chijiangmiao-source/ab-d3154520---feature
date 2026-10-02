"""载荷解析与一次性校验。

服务经真实 API 一次指出全部问题：缺失/重复标识、悬空入口/续点/目标、
无效节点类型、根入口错误。校验在分析之前完成，错误一次性聚合返回。
"""
from __future__ import annotations

from typing import Any

from .model import (
    CALL,
    DANGER,
    JUMP,
    MAX_PROCEDURES,
    RETURN,
    VALID_TYPES,
    Node,
    Procedure,
)


class PayloadError(ValueError):
    """载荷结构本身无法解析（非字典、字段类型错等）。"""


class SourceMissing(Exception):
    """来源审计标识不存在（对应 HTTP 404）。"""


def _is_str(v: Any) -> bool:
    return isinstance(v, str) and v != ""


def parse_and_validate(body: Any) -> tuple[str, str, list[Procedure]]:
    """返回 (audit_id, root_entry, procedures)；无效则抛 PayloadError。"""
    if not isinstance(body, dict):
        raise PayloadError(["请求体必须是 JSON 对象"])

    audit_id = body.get("audit_id")
    root_entry = body.get("root_entry")
    procs_raw = body.get("procedures")

    errors: list[str] = []

    if not _is_str(audit_id):
        errors.append("缺少稳定审计标识 audit_id")
    if not _is_str(root_entry):
        errors.append("缺少根入口 root_entry")
    if not isinstance(procs_raw, list):
        errors.append("procedures 必须是数组")
        raise PayloadError(errors)
    if len(procs_raw) == 0:
        errors.append("至少需要一份规程")
    if len(procs_raw) > MAX_PROCEDURES:
        errors.append(f"规程至多 {MAX_PROCEDURES} 份，收到 {len(procs_raw)} 份")

    procedures: list[Procedure] = []
    seen_pids: set[str] = set()
    # 跨规程节点全局映射：node_id -> (proc_id, node)
    global_nodes: dict[str, tuple[str, Node]] = {}

    for idx, p in enumerate(procs_raw):
        if not isinstance(p, dict):
            errors.append(f"规程[{idx}] 必须是对象")
            continue
        pid = p.get("id")
        entry = p.get("entry")
        nodes_raw = p.get("nodes")

        if not _is_str(pid):
            errors.append(f"规程[{idx}] 缺少标识 id")
            pid = pid if isinstance(pid, str) else f"<invalid:{idx}>"
        elif pid in seen_pids:
            errors.append(f"规程标识重复: {pid}")
        seen_pids.add(pid)

        proc = Procedure(pid=pid, entry=entry if _is_str(entry) else "", nodes={})

        if not _is_str(entry):
            errors.append(f"规程 {pid} 缺少入口 entry")
        if not isinstance(nodes_raw, list) or len(nodes_raw) == 0:
            errors.append(f"规程 {pid} 的 nodes 必须是非空数组")
            nodes_raw = []

        local_seen: set[str] = set()
        for j, n in enumerate(nodes_raw):
            if not isinstance(n, dict):
                errors.append(f"规程 {pid} 节点[{j}] 必须是对象")
                continue
            nid = n.get("id")
            ntype = n.get("type")
            if not _is_str(nid):
                errors.append(f"规程 {pid} 节点[{j}] 缺少 id")
                continue
            if nid in local_seen:
                errors.append(f"规程 {pid} 内节点标识重复: {nid}")
            local_seen.add(nid)

            if ntype not in VALID_TYPES:
                errors.append(
                    f"节点 {pid}.{nid} 的类型无效: {ntype!r}，"
                    f"允许 {sorted(VALID_TYPES)}"
                )
                continue

            node = Node(nid=nid, ntype=ntype, proc=pid)
            if ntype == JUMP:
                node.target = n.get("next") if _is_str(n.get("next")) else None
                if node.target is None:
                    errors.append(f"跳转节点 {pid}.{nid} 缺少下一节点 next")
            elif ntype == CALL:
                tgt = n.get("target")
                cont = n.get("cont")
                node.target = tgt if _is_str(tgt) else None
                node.cont = cont if _is_str(cont) else None
                if node.target is None:
                    errors.append(f"调用节点 {pid}.{nid} 缺少目标 target")
                if node.cont is None:
                    errors.append(f"调用节点 {pid}.{nid} 缺少返回续点 cont")
            # return / danger 无字段

            proc.nodes[nid] = node
            if nid in global_nodes:
                other_pid = global_nodes[nid][0]
                errors.append(
                    f"节点标识 {nid} 在规程 {other_pid} 与 {pid} 间重复"
                )
            global_nodes[nid] = (pid, node)

        procedures.append(proc)

    # 结构性引用校验：入口 / 跳转目标 / 调用目标与续点
    proc_by_id = {p.pid: p for p in procedures}
    for p in procedures:
        if p.entry and p.entry not in p.nodes:
            errors.append(f"规程 {p.pid} 的入口 {p.entry} 悬空（节点不存在）")
        for nid, node in p.nodes.items():
            if node.ntype == JUMP:
                tgt = node.target
                if tgt is not None and tgt not in p.nodes:
                    errors.append(
                        f"跳转节点 {p.pid}.{nid} 的目标 {tgt} 悬空"
                        f"（规程 {p.pid} 内无此节点）"
                    )
            elif node.ntype == CALL:
                tgt, cont = node.target, node.cont
                if tgt is not None and tgt not in proc_by_id:
                    errors.append(
                        f"调用节点 {p.pid}.{nid} 的目标规程 {tgt} 悬空"
                    )
                if cont is not None and cont not in p.nodes:
                    errors.append(
                        f"调用节点 {p.pid}.{nid} 的返回续点 {cont} 悬空"
                        f"（规程 {p.pid} 内无此节点）"
                    )

    # 根入口：指向一份已存在规程的已存在入口节点
    if _is_str(root_entry):
        root_proc = proc_by_id.get(root_entry)
        if root_proc is None:
            errors.append(
                f"根入口错误: 不存在标识为 {root_entry} 的规程"
            )
        elif not root_proc.entry or root_proc.entry not in root_proc.nodes:
            errors.append(f"根入口错误: 规程 {root_entry} 的入口无效")

    if errors:
        raise PayloadError(errors)

    return audit_id, root_entry, procedures


def parse_and_validate_disposal(body: Any, source_of) -> tuple:
    """校验处置载荷，返回 (disposal_id, audit_id, costs, source)。

    source_of(audit_id) -> 冻结审计记录 | None。错误一次性聚合：标识缺
    失、来源结论安全、代价表节点遗漏/重复/未知、非法代价；来源不存在
    抛 SourceMissing。任何拒绝都不触碰已冻结的审计与方案。
    """
    if not isinstance(body, dict):
        raise PayloadError(["请求体必须是 JSON 对象"])

    disposal_id = body.get("disposal_id")
    audit_id = body.get("audit_id")

    errors: list[str] = []
    if not _is_str(disposal_id):
        errors.append("缺少稳定处置标识 disposal_id")
    if not _is_str(audit_id):
        errors.append("缺少来源审计标识 audit_id")
    if errors:
        raise PayloadError(errors)

    source = source_of(audit_id)
    if source is None:
        raise SourceMissing(f"来源审计不存在: {audit_id}（无冻结结论可处置）")
    if not source["result"]["dangerous_reachable"]:
        raise PayloadError(
            [f"来源审计 {audit_id} 结论为安全，无危险链可处置"]
        )

    procedures = source["procedures"]
    executable: dict[str, Node] = {}
    all_nids: set[str] = set()
    for p in procedures:
        for nid, n in p.nodes.items():
            all_nids.add(nid)
            if n.ntype in (JUMP, CALL, RETURN):
                executable[nid] = n

    costs_raw = body.get("costs")
    if not isinstance(costs_raw, list):
        raise PayloadError(
            ['costs 必须是数组，每项形如 {"node": 节点标识, "cost": 非负整数}']
        )

    errors = []
    costs: dict[str, int] = {}
    seen: set[str] = set()
    for i, item in enumerate(costs_raw):
        if not isinstance(item, dict):
            errors.append(f"代价条目[{i}] 必须是对象")
            continue
        nid = item.get("node")
        cost = item.get("cost")
        if not _is_str(nid):
            errors.append(f"代价条目[{i}] 缺少节点标识 node")
            continue
        if nid in seen:
            errors.append(f"代价表节点重复: {nid}")
        seen.add(nid)
        if nid not in executable:
            if nid in all_nids:
                errors.append(f"节点 {nid} 为危险节点，不属于可执行代价节点")
            else:
                errors.append(f"未知节点: {nid}（来源审计中不存在）")
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
            errors.append(f"非法代价: 节点 {nid} 的代价 {cost!r} 不是非负整数")
        elif nid in executable and nid not in costs:
            costs[nid] = cost

    missing = sorted(nid for nid in executable if nid not in seen)
    if missing:
        errors.append(f"代价表遗漏节点: {', '.join(missing)}")

    if errors:
        raise PayloadError(errors)

    return disposal_id, audit_id, costs, source
