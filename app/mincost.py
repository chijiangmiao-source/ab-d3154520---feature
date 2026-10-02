"""最低代价危险链：min-plus 饱和求解与稳定裁决重放。

在布尔可达性饱和的同一配置空间上，为每个配置 x=(规程, 节点) 计算两个
栈无关摘要（对任意栈内容成立的最小不动点）：

    ret[x]   从 x 执行到本帧 return 的最优 (总代价, 事件数)；不能返回为 ∞
    dng[x]   从 x 抵达危险节点的最优 (总代价, 事件数)；不可达为 ∞

记 c(x) 为节点 x 的处置代价（危险节点无代价），⊕ 为分量相加，min 取
字典序（先总代价、后事件数）：

    return 节点   ret = (c, 1)
    danger 节点   dng = (0, 1)
    jump n→m      ret/dng = (c, 1) ⊕ ret/dng[m]
    call q,cont   ret = (c, 1) ⊕ ret[q.e] ⊕ ret[cont]
                  dng = (c, 1) ⊕ min( dng[q.e], ret[q.e] ⊕ dng[cont] )

调用仅在被调帧确实能返回（ret[q.e] 有限）时才接回续点——调用边绝不
被当作普通跳转，返回与续点在任意嵌套深度下精确配对；危险链代价不是
对既有最短事件链的重排，而是对全部有限执行取 min-plus 最小值。

所有代价非负：从 (∞,∞) 起单调递减迭代必收敛到最小不动点。若最优推
导树在某分支上重复同一配置，删去中间一段即得严格更优（代价不增、
事件更少），故最优推导树高 ≤ 2×配置数，迭代有限步收敛；零代价递归
只停在 ∞，不会振荡。

链裁决：最优 (总代价, 事件数) 确定后，按节点标识序字典序重建最小事
件链（多条最低代价链并存时的稳定裁决）。重放时精确压栈/弹栈，逐步
给出累计代价与调用栈。
"""
from __future__ import annotations

from .model import CALL, DANGER, JUMP, RETURN, CostStep, Procedure

INF = (float("inf"), float("inf"))
RETURN_GOAL = "return"
DANGER_GOAL = "danger"


def _add(a: tuple, b: tuple) -> tuple:
    if a[0] == float("inf") or b[0] == float("inf"):
        return INF
    return (a[0] + b[0], a[1] + b[1])


class CostSolver:
    """min-plus 饱和：既能返回的子规程摘要 ret 与危险链代价 dng。"""

    def __init__(self, procedures: list[Procedure], costs: dict[str, int]):
        self.procs = {p.pid: p for p in procedures}
        self.nodes: dict[tuple[str, str], object] = {
            (p.pid, nid): n for p in procedures for nid, n in p.nodes.items()
        }
        self.configs: list[tuple[str, str]] = list(self.nodes)
        self.entry_of = {p.pid: (p.pid, p.entry) for p in procedures}
        self.cfg_of_nid = {
            nid: (p.pid, nid) for p in procedures for nid in p.nodes
        }
        self.costs = costs
        self.ret: dict[tuple[str, str], tuple] = {}
        self.dng: dict[tuple[str, str], tuple] = {}
        self._saturate()

    def _cost(self, node) -> int:
        if node.ntype in (JUMP, CALL, RETURN):
            return self.costs[node.nid]
        return 0  # 危险节点无代价

    # ---------- min-plus 饱和 ----------
    def _saturate(self) -> None:
        ret = {x: INF for x in self.configs}
        dng = {x: INF for x in self.configs}
        while True:
            changed = False
            for x in self.configs:
                n = self.nodes[x]
                unit = (self._cost(n), 1)
                nr, nd = INF, INF
                if n.ntype == RETURN:
                    nr = unit
                elif n.ntype == DANGER:
                    nd = (0, 1)
                elif n.ntype == JUMP:
                    m = (x[0], n.target)
                    nr = _add(unit, ret[m])
                    nd = _add(unit, dng[m])
                elif n.ntype == CALL:
                    qe = self.entry_of[n.target]
                    cont = (x[0], n.cont)
                    # 整段调用返回（被调帧确实能返回才接回续点）
                    nr = _add(unit, _add(ret[qe], ret[cont]))
                    # 危险在被调帧内，或调用返回后进入续点危险
                    nd = _add(unit, min(dng[qe], _add(ret[qe], dng[cont])))
                if nr < ret[x]:
                    ret[x] = nr
                    changed = True
                if nd < dng[x]:
                    dng[x] = nd
                    changed = True
            if not changed:
                self.ret, self.dng = ret, dng
                return

    # ---------- 结论 ----------
    def _val(self, cfg: tuple[str, str], goal: str) -> tuple:
        return self.ret[cfg] if goal == RETURN_GOAL else self.dng[cfg]

    def min_cost(self, root_proc: str) -> tuple | None:
        """根入口抵达危险节点的最优 (总代价, 事件数)；不可达为 None。"""
        v = self.dng[self.entry_of[root_proc]]
        return None if v[0] == float("inf") else v

    # ---------- 稳定裁决重放 ----------
    def _optimal_actions(self, cfg: tuple[str, str], goal: str) -> list[tuple]:
        """取得最优 (代价, 事件数) 的动作集合，每个动作是一组后继键。"""
        n = self.nodes[cfg]
        val = self._val(cfg, goal)
        unit = (self._cost(n), 1)
        actions: list[tuple] = []
        if n.ntype == JUMP:
            m = (cfg[0], n.target)
            if _add(unit, self._val(m, goal)) == val:
                actions.append(((m, goal),))
        elif n.ntype == CALL:
            qe = self.entry_of[n.target]
            cont = (cfg[0], n.cont)
            if _add(unit, _add(self.ret[qe], self._val(cont, goal))) == val:
                actions.append(((qe, RETURN_GOAL), (cont, goal)))
            if goal == DANGER_GOAL and _add(unit, self.dng[qe]) == val:
                actions.append(((qe, DANGER_GOAL),))
        return actions

    def _build_seq(self, start: tuple[str, str]) -> tuple[str, ...]:
        """重建最优事件链（节点标识序字典序最小），含起点与危险节点。

        后继键的事件数严格小于当前键，故按事件数递增动态规划即可，
        不使用递归，长链不会触及解释器递归深度。
        """
        needed: dict[tuple, None] = {}
        work = [(start, DANGER_GOAL)]
        while work:
            key = work.pop()
            if key in needed:
                continue
            needed[key] = None
            for action in self._optimal_actions(*key):
                for dep in action:
                    if dep not in needed:
                        work.append(dep)
        keys = sorted(needed, key=lambda k: self._val(k[0], k[1])[1])
        seqs: dict[tuple, tuple[str, ...]] = {}
        for key in keys:
            cfg, goal = key
            cands = [
                tuple(nid for dep in action for nid in seqs[dep])
                for action in self._optimal_actions(cfg, goal)
            ]
            seqs[key] = (cfg[1],) + (min(cands) if cands else ())
        return seqs[(start, DANGER_GOAL)]

    def replay(self, root_proc: str) -> list[CostStep]:
        """重放最低代价链：每步携带代价、累计代价与精确调用栈。"""
        start = self.entry_of[root_proc]
        if self.dng[start][0] == float("inf"):
            return []
        seq = self._build_seq(start)
        steps: list[CostStep] = []
        stack: list[tuple[str, str]] = []  # 顶→底：待返回的 (规程, 续点)
        cumulative = 0
        for nid in seq:
            cfg = self.cfg_of_nid[nid]
            n = self.nodes[cfg]
            cumulative += self._cost(n)
            steps.append(CostStep(
                index=len(steps) + 1, node_id=cfg[1], proc=cfg[0],
                kind=n.ntype, target=n.target, cont=n.cont,
                cost=self._cost(n), cumulative=cumulative,
                dangerous=(n.ntype == DANGER),
                stack=[f"{cfg[0]}.{cfg[1]}"]
                + [f"{p}.{c}" for p, c in stack],
            ))
            if n.ntype == CALL:
                stack.insert(0, (cfg[0], n.cont))   # 压栈：待返回续点
            elif n.ntype == RETURN:
                stack.pop(0)                        # 弹栈：精确配对
        return steps
