"""按调用栈精确分析危险可达性（下推系统，单调饱和到最小不动点）。

把规程系统建模为下推系统（PDS），控制位置为“当前帧执行节点”，栈为各
帧待返回的续点：

    普通跳转 n -> m：   (p.n, γ)     → (p.m, γ)
    调用 n→q, 续点 c：  (p.n, γ)     → (q.e_q, (p,c)·γ)
    正常返回 n：        (p.n, (p',c)·γ) → (p'.c, γ)
    危险节点：终止目标。

栈无关摘要（对任意 γ 成立，最小不动点）：

    same_succ[x]  与 x 同一栈内容下可一步到达的帧内配置：
                   * 跳转边 n→m（恒成立）
                   * “整段调用返回”边 n→c（当被调帧入口 can_return）
    reach[x]      same_succ 的自反传递闭包（帧内、净栈不变的可达）
    can_return[x] 从 x 出发能否在本帧层级执行到 return（不要求下方栈）
    danger[x]     从 x 出发（任意嵌套深度）能否抵达危险节点

危险可经由 (a) 帧内净栈不变路径上的 danger 节点，或 (b) 该路径上某个
调用点的被调帧入口 danger 到达。调用仅在被调帧能 can_return 时才作为
同栈后继接回续点——调用边绝不被当作普通图边，返回与续点精确配对。

迭代重算到不动点：每发现新的 can_return 就补入 call→cont 边并重算闭包。
配置集有限，故单调有界必终止，且对无界递归成立（不截断栈、不设深度）。

证明重放：在有限摘要图上取最短事件路径，把其中的 call→cont 边递归展开
为“下钻被调帧—跑到 return—弹栈回续点”，得到有限且每步带栈的链。
"""
from __future__ import annotations

from collections import deque

from .model import CALL, DANGER, JUMP, RETURN, Procedure, Step

DANGER_GOAL = "danger"
RETURN_GOAL = "return"


class Analyzer:
    def __init__(self, procedures: list[Procedure]):
        self.procs = {p.pid: p for p in procedures}
        self.configs: list[tuple[str, str]] = [
            (p.pid, nid) for p in procedures for nid in p.nodes
        ]
        self.nodes: dict[tuple[str, str], object] = {
            (p.pid, nid): n for p in procedures for nid, n in p.nodes.items()
        }
        self.entry_of = {p.pid: (p.pid, p.entry) for p in procedures}

        self.same_succ: dict[tuple[str, str], set[tuple[str, str]]] = {}
        self.edge_kind: dict[tuple[tuple[str, str], tuple[str, str]], str] = {}
        self.reach: dict[tuple[str, str], set[tuple[str, str]]] = {}
        self.can_return: set[tuple[str, str]] = set()
        self.danger: set[tuple[str, str]] = set()

        self._saturate()

    # ---------- 饱和 ----------
    def _jump_succ(self, cfg: tuple[str, str]):
        node = self.nodes[cfg]
        if node.ntype == JUMP:
            return {(cfg[0], node.target)}
        return set()

    def _saturate(self) -> None:
        prev_cr: set[tuple[str, str]] = set()
        prev_dg: set[tuple[str, str]] = set()
        while True:
            # 1) 同栈一步后继：跳转 + 已可返回调用的 call→cont
            same_succ: dict[tuple[str, str], set[tuple[str, str]]] = {}
            edge_kind: dict[tuple[tuple[str, str], tuple[str, str]], str] = {}
            for cfg in self.configs:
                nxt = self._jump_succ(cfg)
                for t in nxt:
                    edge_kind[(cfg, t)] = JUMP
                node = self.nodes[cfg]
                if node.ntype == CALL:
                    qentry = self.entry_of[node.target]
                    if qentry in self.can_return:
                        ret = (cfg[0], node.cont)
                        nxt.add(ret)
                        edge_kind[(cfg, ret)] = "call-return"
                same_succ[cfg] = nxt

            # 2) 帧内传递闭包
            reach = {x: self._closure(x, same_succ) for x in self.configs}

            # 3) can_return / danger
            can_return: set[tuple[str, str]] = set()
            danger: set[tuple[str, str]] = set()
            for x in self.configs:
                for y in reach[x]:
                    yn = self.nodes[y]
                    if yn.ntype == RETURN:
                        can_return.add(x)
                    if yn.ntype == DANGER:
                        danger.add(x)
                    if yn.ntype == CALL:
                        qentry = self.entry_of[yn.target]
                        # 被调帧入口危险（无论其是否返回）→ x 危险
                        if qentry in danger or qentry in prev_dg:
                            danger.add(x)
            if can_return == prev_cr and danger == prev_dg:
                self.same_succ = same_succ
                self.edge_kind = edge_kind
                self.reach = reach
                self.can_return = can_return
                self.danger = danger
                return
            prev_cr, prev_dg = can_return, danger
            # 下一轮用新结论
            self.can_return, self.danger = can_return, danger

    @staticmethod
    def _closure(start, same_succ) -> set[tuple[str, str]]:
        seen = {start}
        dq = deque([start])
        while dq:
            cur = dq.popleft()
            for nxt in same_succ.get(cur, ()):  # 同帧配置
                if nxt[0] == cur[0] and nxt not in seen:
                    seen.add(nxt)
                    dq.append(nxt)
        return seen

    # ---------- 结论 ----------
    def root_dangerous(self, root_proc: str) -> bool:
        return self.entry_of[root_proc] in self.danger

    def summary(self, root_proc: str) -> dict:
        e = self.entry_of[root_proc]
        return {
            "can_return": sorted(f"{p}.{n}" for (p, n) in self.can_return),
            "dangerous_entries": sorted(
                f"{p}.{self.procs[p].entry}" for (p, n) in self.danger
                if n == self.procs[p].entry
            ),
            "root_entry": f"{root_proc}.{self.procs[root_proc].entry}",
            "root_can_return": e in self.can_return,
            "root_dangerous": e in self.danger,
        }

    # ---------- 证明重放 ----------
    def replay(self, root_proc: str) -> list[Step]:
        steps: list[Step] = []
        if not self.root_dangerous(root_proc):
            return steps
        self._run(self.entry_of[root_proc], (), DANGER_GOAL, steps)
        for i, s in enumerate(steps, 1):
            s.index = i
        return steps

    def _shortest_event_path(
        self, start: tuple[str, str], goal: str
    ) -> list[tuple[str, str]]:
        """同帧内沿 same_succ 到最近“事件节点”的最短配置路径。

        DANGER 目标事件：帧内 danger 节点，或被调入口危险的调用点。
        RETURN 目标事件：帧内 return 节点。
        """
        def is_event(cfg):
            n = self.nodes[cfg]
            if goal == RETURN_GOAL:
                return n.ntype == RETURN
            if n.ntype == DANGER:
                return True
            if n.ntype == CALL and self.entry_of[n.target] in self.danger:
                return True
            return False

        prev: dict[tuple[str, str], tuple[str, str] | None] = {start: None}
        dq = deque([start])
        target = None
        while dq:
            cur = dq.popleft()
            if is_event(cur):
                target = cur
                break
            for nxt in self.same_succ.get(cur, ()):
                if nxt[0] == cur[0] and nxt not in prev:
                    prev[nxt] = cur
                    dq.append(nxt)
        if target is None:
            raise RuntimeError("饱和结论与重放不一致（不应发生）")
        path = []
        c = target
        while c is not None:
            path.append(c)
            c = prev[c]
        path.reverse()
        return path

    def _snapshot(self, cfg, call_stack) -> list[str]:
        """当前节点为帧顶；其下为待返回的 规程.续点。"""
        snap = [f"{cfg[0]}.{cfg[1]}"]
        for (cpid, ccont) in call_stack:
            snap.append(f"{cpid}.{ccont}")
        return snap

    def _emit(self, cfg, call_stack, steps) -> None:
        node = self.nodes[cfg]
        steps.append(Step(
            index=len(steps) + 1, node_id=cfg[1], proc=cfg[0],
            kind=node.ntype, target=node.target, cont=node.cont,
            dangerous=(node.ntype == DANGER),
            stack=self._snapshot(cfg, call_stack),
        ))

    def _run(self, start, call_stack, goal, steps) -> tuple:
        """在帧顶执行直到本帧 goal（danger/return）。

        返回执行 goal 节点后的栈（RETURN 时已弹栈）。展开过程严格下钻
        被调帧；每条被展开调用都由最短摘要路径保证有限，故即使无界递归
        重放也终止。
        """
        path = self._shortest_event_path(start, goal)
        # 逐边走；path 相邻两节点间要么是 jump，要么是 call-return（需展开）
        cur = path[0]
        for nxt in path[1:]:
            kind = self.edge_kind[(cur, nxt)]
            self._emit(cur, call_stack, steps)
            if kind == JUMP:
                cur = nxt
                continue
            # call-return：cur 为调用点，nxt 为同帧续点；展开被调帧
            node = self.nodes[cur]
            qentry = self.entry_of[node.target]
            pushed = ((cur[0], node.cont),) + call_stack
            # 下钻被调帧并在其 return 后弹栈
            after = self._run(qentry, pushed, RETURN_GOAL, steps)
            # after 即恢复为 call_stack（被调帧已返回）
            call_stack = after
            cur = nxt
        # 到达事件节点
        self._emit(cur, call_stack, steps)
        node = self.nodes[cur]
        if node.ntype == DANGER:
            return call_stack
        if node.ntype == RETURN:
            # 弹出本帧，回到调用方续点
            return call_stack[1:]
        if node.ntype == CALL:
            # 危险在被调帧：下钻即终止于危险
            qentry = self.entry_of[node.target]
            pushed = ((cur[0], node.cont),) + call_stack
            return self._run(qentry, pushed, DANGER_GOAL, steps)
        return call_stack
