"""处置方案：min-plus 最低代价链、零代价递归收敛、冻结回放与冲突拒绝。"""
from __future__ import annotations

import unittest

from app.mincost import INF, CostSolver
from app.model import CALL, DANGER, JUMP, RETURN
from app.store import Store
from app.validate import PayloadError, SourceMissing
from tests.test_audit import mkproc, payload

# 嵌套调用正常返回后，根规程才在续点进入危险节点（与审计冒烟同一构型）
NESTED_PROCS = [
    mkproc("main", "a0", [("a0", CALL, "P", "a1"), ("a1", DANGER)]),
    mkproc("P", "p0", [("p0", CALL, "Q", "p1"), ("p1", RETURN)]),
    mkproc("Q", "q0", [("q0", RETURN)]),
]
NESTED_COSTS = {"a0": 2, "p0": 3, "q0": 7, "p1": 5}

# 危险链之外挂有零代价自递归与零代价跳转自环：求解必须收敛
ZERO_PROCS = [
    mkproc("main", "a0", [("a0", CALL, "P", "a1"), ("a1", DANGER)]),
    mkproc("P", "p0", [("p0", RETURN)]),
    mkproc("loop", "l0", [("l0", CALL, "loop", "l1"), ("l1", RETURN)]),
    mkproc("spin", "s0", [("s0", JUMP, "s0")]),
]
ZERO_COSTS = {"a0": 0, "p0": 0, "l0": 0, "l1": 0, "s0": 0}


def disp_payload(disp_id, audit_id, cost_pairs):
    return {
        "disposal_id": disp_id,
        "audit_id": audit_id,
        "costs": [{"node": n, "cost": c} for n, c in cost_pairs],
    }


class TestCostSolver(unittest.TestCase):
    def test_nested_return_then_danger_cont_min_cost(self):
        """递归子规程返回后进入危险续点：最低总代价与逐步累计。"""
        solver = CostSolver(NESTED_PROCS, NESTED_COSTS)
        self.assertEqual(solver.min_cost("main"), (17, 5))
        steps = solver.replay("main")
        self.assertEqual([s.kind for s in steps],
                         [CALL, CALL, RETURN, RETURN, DANGER])
        self.assertEqual([s.cost for s in steps], [2, 3, 7, 5, 0])
        self.assertEqual([s.cumulative for s in steps], [2, 5, 12, 17, 17])
        self.assertEqual(steps[0].stack, ["main.a0"])
        self.assertEqual(steps[1].stack, ["P.p0", "main.a1"])
        self.assertEqual(steps[2].stack, ["Q.q0", "P.p1", "main.a1"])
        self.assertEqual(steps[3].stack, ["P.p1", "main.a1"])
        self.assertEqual(steps[4].stack, ["main.a1"])
        # min-plus 摘要：既能返回的子规程 ret，与危险链代价 dng
        self.assertEqual(solver.ret[("Q", "q0")], (7, 1))
        self.assertEqual(solver.ret[("P", "p0")], (15, 3))
        self.assertEqual(solver.dng[("main", "a0")], (17, 5))
        self.assertEqual(solver.dng[("P", "p0")], INF)   # P 帧内无危险
        self.assertEqual(solver.ret[("main", "a0")], INF)  # 续点是危险

    def test_zero_cost_recursion_converges(self):
        """零代价自递归/自环只停在 ∞，求解收敛且不被无根据点亮。"""
        solver = CostSolver(ZERO_PROCS, ZERO_COSTS)  # 必须终止
        self.assertEqual(solver.min_cost("main"), (0, 3))
        steps = solver.replay("main")
        self.assertEqual([s.kind for s in steps], [CALL, RETURN, DANGER])
        self.assertEqual([s.cumulative for s in steps], [0, 0, 0])
        self.assertEqual(solver.ret[("loop", "l0")], INF)
        self.assertEqual(solver.dng[("loop", "l0")], INF)
        self.assertEqual(solver.ret[("spin", "s0")], INF)
        self.assertEqual(solver.dng[("spin", "s0")], INF)

    def test_danger_at_root_entry_zero_cost(self):
        procs = [mkproc("main", "a0", [("a0", DANGER)])]
        solver = CostSolver(procs, {})
        self.assertEqual(solver.min_cost("main"), (0, 1))
        steps = solver.replay("main")
        self.assertEqual(len(steps), 1)
        self.assertTrue(steps[0].dangerous)
        self.assertEqual(steps[0].cumulative, 0)

    def test_replay_is_stable(self):
        """同一求解重复进行，链裁决完全一致（稳定裁决）。"""
        a = CostSolver(NESTED_PROCS, NESTED_COSTS).replay("main")
        shuffled = dict(reversed(list(NESTED_COSTS.items())))
        b = CostSolver(NESTED_PROCS, shuffled).replay("main")
        self.assertEqual([s.node_id for s in a], [s.node_id for s in b])
        self.assertEqual([s.cumulative for s in a], [s.cumulative for s in b])


class TestDisposalStore(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        r, e, c = self.store.analyze(payload("D-NESTED", "main", NESTED_PROCS))
        assert e is None and c is None and r["dangerous_reachable"]

    def _dispose(self, disp_id, audit_id, cost_pairs):
        return self.store.dispose(disp_payload(disp_id, audit_id, cost_pairs))

    def test_freeze_replay_and_audit_untouched(self):
        r, conflict = self._dispose("DISP-1", "D-NESTED", NESTED_COSTS.items())
        self.assertIsNone(conflict)
        self.assertFalse(r["replayed"])
        self.assertEqual(r["min_cost"], 17)
        self.assertEqual(r["events"], 5)
        self.assertEqual(r["danger_node"], "main.a1")
        self.assertEqual([s["kind"] for s in r["steps"]],
                         ["call", "call", "return", "return", "danger"])
        self.assertEqual([s["cumulative"] for s in r["steps"]],
                         [2, 5, 12, 17, 17])

        # 同载荷重传 → 回放冻结方案（证据一致）
        r2, c2 = self._dispose("DISP-1", "D-NESTED", NESTED_COSTS.items())
        self.assertIsNone(c2)
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["steps"], r["steps"])
        self.assertEqual(r2["min_cost"], r["min_cost"])

        # 刷新后按处置标识读取完全相同的证据
        got = self.store.get_disposal("DISP-1")
        self.assertIsNotNone(got)
        self.assertEqual(got["steps"], r["steps"])
        self.assertEqual(got["conclusion"], r["conclusion"])

        # 原危险审计仍可读取且未被改写
        audit = self.store.get("D-NESTED")
        self.assertTrue(audit["dangerous_reachable"])
        self.assertEqual([s["kind"] for s in audit["steps"]],
                         ["call", "call", "return", "return", "danger"])

    def test_conflict_on_changed_costs(self):
        self._dispose("DISP-2", "D-NESTED", NESTED_COSTS.items())
        changed = list(NESTED_COSTS.items())
        changed[0] = ("a0", 99)
        r, conflict = self._dispose("DISP-2", "D-NESTED", changed)
        self.assertIsNone(r)
        self.assertIsNotNone(conflict)
        self.assertIn("改换", conflict)
        # 冲突不改写已冻结方案
        self.assertEqual(self.store.get_disposal("DISP-2")["min_cost"], 17)

    def test_conflict_on_changed_source(self):
        self._dispose("DISP-3", "D-NESTED", NESTED_COSTS.items())
        r, e, c = self.store.analyze(payload("D-NESTED-2", "main", NESTED_PROCS))
        assert r is not None
        r2, conflict = self._dispose("DISP-3", "D-NESTED-2", NESTED_COSTS.items())
        self.assertIsNone(r2)
        self.assertIn("改换", conflict)

    def test_source_missing(self):
        with self.assertRaises(SourceMissing):
            self._dispose("DISP-4", "NO-SUCH", NESTED_COSTS.items())

    def test_source_safe_rejected(self):
        safe = [
            mkproc("main", "a0", [("a0", CALL, "P", "a1"), ("a1", RETURN)]),
            mkproc("P", "p0", [("p0", RETURN)]),
        ]
        self.store.analyze(payload("D-SAFE", "main", safe))
        with self.assertRaises(PayloadError) as ctx:
            self._dispose("DISP-5", "D-SAFE", [("a0", 1), ("p0", 1)])
        self.assertIn("结论为安全", str(ctx.exception.args[0]))

    def test_cost_table_errors_aggregated(self):
        costs = [
            ("a0", 2), ("a0", 3),      # 重复
            ("ghost", 1),              # 未知节点
            ("a1", 1),                 # 危险节点不属于可执行代价节点
            ("p0", -1),                # 负代价
            ("q0", 1.5),               # 非整数
            ("p1", True),              # 布尔不是非负整数
        ]
        with self.assertRaises(PayloadError) as ctx:
            self._dispose("DISP-6", "D-NESTED", costs)
        msg = " | ".join(ctx.exception.args[0])
        self.assertIn("重复", msg)
        self.assertIn("未知节点", msg)
        self.assertIn("危险节点", msg)
        self.assertIn("非法代价", msg)
        # 失败的处置不留下任何冻结方案，也不改写原审计
        self.assertIsNone(self.store.get_disposal("DISP-6"))
        self.assertTrue(self.store.get("D-NESTED")["dangerous_reachable"])

    def test_missing_node(self):
        costs = [("a0", 2), ("p0", 3), ("q0", 7)]  # 缺 p1
        with self.assertRaises(PayloadError) as ctx:
            self._dispose("DISP-7", "D-NESTED", costs)
        msg = str(ctx.exception.args[0])
        self.assertIn("遗漏", msg)
        self.assertIn("p1", msg)

    def test_dispose_danger_at_entry_empty_costs(self):
        procs = [mkproc("main", "a0", [("a0", DANGER)])]
        self.store.analyze(payload("D-ENTRY", "main", procs))
        r, conflict = self.store.dispose(
            {"disposal_id": "DISP-0", "audit_id": "D-ENTRY", "costs": []}
        )
        self.assertIsNone(conflict)
        self.assertEqual(r["min_cost"], 0)
        self.assertEqual(r["events"], 1)


if __name__ == "__main__":
    unittest.main()
