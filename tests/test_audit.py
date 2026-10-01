"""分析器与服务的测试：递归返回、悬空调用、冻结回放、无界递归等。"""
from __future__ import annotations

import unittest

from app.analyzer import Analyzer
from app.model import CALL, DANGER, JUMP, RETURN, Node, Procedure
from app.store import Store
from app.validate import PayloadError, parse_and_validate


def mkproc(pid: str, entry: str, nodes: list[tuple]) -> Procedure:
    """nodes: (id, type, next?, target?, cont?)"""
    ns = {}
    for tup in nodes:
        nid, ntype = tup[0], tup[1]
        n = Node(nid=nid, ntype=ntype, proc=pid)
        if ntype == JUMP:
            n.target = tup[2]
        elif ntype == CALL:
            n.target = tup[2]
            n.cont = tup[3]
        ns[nid] = n
    return Procedure(pid=pid, entry=entry, nodes=ns)


def payload(audit_id, root, procs):
    return {
        "audit_id": audit_id,
        "root_entry": root,
        "procedures": [
            {"id": p.pid, "entry": p.entry,
             "nodes": [
                 {"id": n.nid, "type": n.ntype,
                  **({"next": n.target} if n.ntype == JUMP else {}),
                  **({"target": n.target, "cont": n.cont} if n.ntype == CALL else {})}
                 for n in p.nodes.values()
             ]}
            for p in procs
        ],
    }


class TestAnalyzer(unittest.TestCase):
    def test_nested_return_then_dangerous_cont(self):
        """递归式嵌套调用正常返回后，才在根规程续点进入危险节点。"""
        main = mkproc("main", "a0", [
            ("a0", CALL, "P", "a1"),
            ("a1", DANGER),
        ])
        P = mkproc("P", "p0", [
            ("p0", CALL, "Q", "p1"),
            ("p1", RETURN),
        ])
        Q = mkproc("Q", "q0", [("q0", RETURN)])
        an = Analyzer([main, P, Q])
        self.assertTrue(an.root_dangerous("main"))
        steps = an.replay("main")
        kinds = [s.kind for s in steps]
        self.assertEqual(kinds, [CALL, CALL, RETURN, RETURN, DANGER])
        # 每步栈（顶→底）
        self.assertEqual(steps[0].stack, ["main.a0"])
        self.assertEqual(steps[1].stack, ["P.p0", "main.a1"])
        self.assertEqual(steps[2].stack, ["Q.q0", "P.p1", "main.a1"])
        self.assertEqual(steps[3].stack, ["P.p1", "main.a1"])
        self.assertEqual(steps[4].stack, ["main.a1"])
        self.assertTrue(steps[-1].dangerous)

    def test_danger_only_after_nonreturning_recursion_is_safe(self):
        """无界自递归永不返回，危险仅在续点之后：必须判安全且分析终止。

        不截断栈、不设递归深度——最小不动点下 can_return 不被无根据假设点亮。
        """
        main = mkproc("main", "a0", [
            ("a0", CALL, "loop", "a1"),
            ("a1", DANGER),
        ])
        loop = mkproc("loop", "l0", [
            ("l0", CALL, "loop", "l1"),
            ("l1", RETURN),
        ])
        an = Analyzer([main, loop])  # 必须终止
        self.assertFalse(an.root_dangerous("main"))
        self.assertNotIn(("loop", "l0"), an.can_return)
        self.assertNotIn(("main", "a0"), an.can_return)

    def test_mutual_recursion_never_returns_safe(self):
        main = mkproc("main", "a0", [
            ("a0", JUMP, "a1"),
            ("a1", CALL, "B", "a2"),
            ("a2", DANGER),
        ])
        B = mkproc("B", "b0", [
            ("b0", CALL, "main", "b1"),
            ("b1", RETURN),
        ])
        an = Analyzer([main, B])
        self.assertFalse(an.root_dangerous("main"))

    def test_danger_inside_callee_reachable_without_return(self):
        main = mkproc("main", "a0", [
            ("a0", CALL, "P", "a1"),  # P 不返回，但内部即危险
            ("a1", RETURN),
        ])
        P = mkproc("P", "p0", [
            ("p0", JUMP, "p1"),
            ("p1", DANGER),
        ])
        an = Analyzer([main, P])
        self.assertTrue(an.root_dangerous("main"))
        steps = an.replay("main")
        self.assertEqual([s.kind for s in steps], [CALL, JUMP, DANGER])
        self.assertEqual(steps[-1].stack, ["P.p1", "main.a1"])

    def test_safe_root_no_danger(self):
        main = mkproc("main", "a0", [
            ("a0", CALL, "P", "a1"),
            ("a1", RETURN),
        ])
        P = mkproc("P", "p0", [("p0", RETURN)])
        an = Analyzer([main, P])
        self.assertFalse(an.root_dangerous("main"))
        self.assertEqual(an.replay("main"), [])

    def test_jump_chain(self):
        main = mkproc("main", "a0", [
            ("a0", JUMP, "a1"),
            ("a1", JUMP, "a2"),
            ("a2", DANGER),
        ])
        an = Analyzer([main])
        self.assertTrue(an.root_dangerous("main"))
        self.assertEqual([s.kind for s in an.replay("main")],
                         [JUMP, JUMP, DANGER])


class TestValidation(unittest.TestCase):
    def _errs(self, body):
        try:
            parse_and_validate(body)
        except PayloadError as e:
            return list(e.args[0])
        self.fail("应当校验失败")

    def test_aggregated_errors(self):
        body = {
            "audit_id": "",
            "root_entry": "nope",
            "procedures": [
                {"id": "p", "entry": "missing", "nodes": [
                    {"id": "x", "type": "weird"},
                    {"id": "x", "type": "jump", "next": "ghost"},
                    {"id": "c", "type": "call", "target": "gone", "cont": "nocont"},
                ]},
            ],
        }
        errs = " | ".join(self._errs(body))
        self.assertIn("audit_id", errs)
        self.assertIn("悬空", errs)          # 入口悬空
        self.assertIn("类型无效", errs)
        self.assertIn("重复", errs)
        self.assertIn("根入口错误", errs)

    def test_dangling_call_target_and_cont(self):
        body = payload("A1", "main", [mkproc("main", "a0", [
            ("a0", CALL, "ghost", "a1"),
            ("a1", RETURN),
        ])])
        errs = " | ".join(self._errs(body))
        self.assertIn("目标规程 ghost 悬空", errs)

        body2 = payload("A2", "main", [
            mkproc("main", "a0", [("a0", CALL, "sub", "zzz")]),
            mkproc("sub", "s0", [("s0", RETURN)]),
        ])
        errs2 = " | ".join(self._errs(body2))
        self.assertIn("返回续点 zzz 悬空", errs2)

    def test_duplicate_proc_id(self):
        body = payload("A3", "p", [
            mkproc("p", "a", [("a", RETURN)]),
            mkproc("p", "b", [("b", DANGER)]),
        ])
        errs = " | ".join(self._errs(body))
        self.assertIn("规程标识重复", errs)

    def test_too_many_procedures(self):
        procs = [mkproc(f"p{i}", "e", [("e", RETURN)]) for i in range(13)]
        errs = " | ".join(self._errs(payload("A4", "p0", procs)))
        self.assertIn("至多 12", errs)

    def test_valid_passes(self):
        procs = [mkproc("main", "a0", [("a0", RETURN)])]
        aid, root, got = parse_and_validate(payload("A5", "main", procs))
        self.assertEqual(aid, "A5")
        self.assertEqual(root, "main")


class TestFreezeReplay(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.procs = [
            mkproc("main", "a0", [("a0", CALL, "P", "a1"), ("a1", DANGER)]),
            mkproc("P", "p0", [("p0", RETURN)]),
        ]

    def test_freeze_then_replay_same_payload(self):
        body = payload("F1", "main", self.procs)
        r1, e1, c1 = self.store.analyze(body)
        self.assertIsNone(e1)
        self.assertIsNone(c1)
        self.assertFalse(r1["replayed"])
        self.assertTrue(r1["dangerous_reachable"])
        first = r1["steps"]

        r2, _, c2 = self.store.analyze(payload("F1", "main", self.procs))
        self.assertIsNone(c2)
        self.assertTrue(r2["replayed"])            # 回放冻结结论
        self.assertEqual(r2["steps"], first)       # 证据一致
        self.assertEqual(r2["conclusion"], r1["conclusion"])

    def test_changed_payload_rejected(self):
        self.store.analyze(payload("F2", "main", self.procs))
        changed = [
            mkproc("main", "a0", [("a0", CALL, "P", "a1"), ("a1", RETURN)]),
            mkproc("P", "p0", [("p0", RETURN)]),
        ]
        r3, errs, conflict = self.store.analyze(payload("F2", "main", changed))
        self.assertIsNone(r3)
        self.assertIsNone(errs)
        self.assertIsNotNone(conflict)
        self.assertIn("改换载荷被拒绝", conflict)

    def test_evidence_get(self):
        self.store.analyze(payload("F3", "main", self.procs))
        rec = self.store.get("F3")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["audit_id"], "F3")
        self.assertIsNone(self.store.get("missing"))


if __name__ == "__main__":
    unittest.main()
