"""一次性 verify 服务：构建检查 + 代码测试 + HTTP 冒烟，跑完即退并以状态码报告。

两种用法：
  1) 本地：python verify.py            自行起一个真实 HTTP 服务再冒烟
  2) Compose：WEB_URL=http://web:8080  对已健康的 web 服务冒烟

围绕关键场景：递归返回后才进入危险续点、悬空调用拒绝、冻结回放
（同标识同载荷回放 / 改换载荷拒绝 / 刷新后按标识取证据）。
退出码：全部通过 0，任一失败 1。
"""
from __future__ import annotations

import json
import os
import py_compile
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

PASS, FAIL = "✅", "❌"
results: list[tuple[bool, str]] = []


def check(ok: bool, name: str, detail: str = "") -> bool:
    results.append((ok, name))
    print(f"  {PASS if ok else FAIL} {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok and detail:
        print(f"       {detail}")
    return ok


# ---------- 1) 构建检查：全部源码字节码编译 ----------
def build_check() -> bool:
    print("\n[1/3] 构建检查（py_compile）")
    bad = []
    for root, _dirs, files in os.walk(os.path.join(HERE, "app")):
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(root, f)
                try:
                    py_compile.compile(path, doraise=True)
                except py_compile.PyCompileError as exc:
                    bad.append(f"{path}: {exc}")
    check(not bad, "全部 app 源码可编译", "; ".join(bad))
    return not bad


# ---------- 2) 代码测试 ----------
def unit_tests() -> bool:
    print("\n[2/3] 代码测试（unittest）")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_audit")
    runner = unittest.TextTestRunner(verbosity=1, stream=sys.stdout)
    res = runner.run(suite)
    ok = res.wasSuccessful()
    check(ok, f"单元测试 {res.testsRun} 项全通过",
          f"失败 {len(res.failures)} 错误 {len(res.errors)}")
    return ok


# ---------- 3) HTTP 冒烟 ----------
def request(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def wait_healthy(base: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code, obj = request("GET", base + "/health")
            if code == 200 and obj.get("status") == "ok":
                return True
        except Exception:
            time.sleep(0.3)
    return False


NESTED = {
    "audit_id": "SMOKE-NESTED", "root_entry": "main",
    "procedures": [
        {"id": "main", "entry": "a0", "nodes": [
            {"id": "a0", "type": "call", "target": "P", "cont": "a1"},
            {"id": "a1", "type": "danger"}]},
        {"id": "P", "entry": "p0", "nodes": [
            {"id": "p0", "type": "call", "target": "Q", "cont": "p1"},
            {"id": "p1", "type": "return"}]},
        {"id": "Q", "entry": "q0", "nodes": [
            {"id": "q0", "type": "return"}]},
    ],
}

DANGLING = {
    "audit_id": "SMOKE-DANGLING", "root_entry": "main",
    "procedures": [
        {"id": "main", "entry": "a0", "nodes": [
            {"id": "a0", "type": "call", "target": "ghost", "cont": "a1"},
            {"id": "a1", "type": "return"}]}],
}

RECURSION_SAFE = {
    "audit_id": "SMOKE-RECURSION", "root_entry": "main",
    "procedures": [
        {"id": "main", "entry": "a0", "nodes": [
            {"id": "a0", "type": "call", "target": "loop", "cont": "a1"},
            {"id": "a1", "type": "danger"}]},
        {"id": "loop", "entry": "l0", "nodes": [
            {"id": "l0", "type": "call", "target": "loop", "cont": "l1"},
            {"id": "l1", "type": "return"}]}],
}


def http_smoke(base: str) -> bool:
    print(f"\n[3/3] HTTP 冒烟（{base}）")
    ok = True

    code, obj = request("GET", base + "/health")
    ok &= check(code == 200 and obj["status"] == "ok", "健康路径反映可用性", f"{code} {obj}")

    with urllib.request.urlopen(base + "/", timeout=5) as r:
        page = r.read().decode()
    ok &= check(r.status == 200 and "安全审计" in page, "页面可访问", f"status={r.status}")

    # 递归/嵌套返回后才进入危险续点：逐步链与每步栈
    code, obj = request("POST", base + "/api/analyze", NESTED)
    res = obj.get("result", {})
    kinds = [s["kind"] for s in res.get("steps", [])]
    stacks = [s["stack"] for s in res.get("steps", [])]
    ok &= check(code == 200 and obj["ok"], "嵌套返回-危险续点分析 200", str(obj)[:200])
    ok &= check(res.get("dangerous_reachable") is True, "结论=危险可达", str(res.get("conclusion")))
    ok &= check(kinds == ["call", "call", "return", "return", "danger"],
                "链=call,call,return,return,danger", str(kinds))
    expect_stack = [
        ["main.a0"],
        ["P.p0", "main.a1"],
        ["Q.q0", "P.p1", "main.a1"],
        ["P.p1", "main.a1"],
        ["main.a1"],
    ]
    ok &= check(stacks == expect_stack, "每步调用栈精确（压栈/弹栈/续点）",
                f"got={stacks}")
    first_conclusion = res.get("conclusion")

    # 悬空调用一次拒绝
    code, obj = request("POST", base + "/api/analyze", DANGLING)
    errs = obj.get("errors", [])
    ok &= check(code == 400 and not obj["ok"], "悬空调用拒绝 HTTP 400", str(obj)[:200])
    ok &= check(any("目标规程 ghost 悬空" in e for e in errs), "错误信息指出悬空目标", str(errs))

    # 无界递归（永不返回）→ 安全，且服务即时返回（无截断/无深度限制）
    t0 = time.time()
    code, obj = request("POST", base + "/api/analyze", RECURSION_SAFE)
    elapsed = time.time() - t0
    r2 = obj.get("result", {})
    ok &= check(code == 200 and r2.get("dangerous_reachable") is False,
                "无界递归永不返回→安全", str(obj)[:200])
    ok &= check(elapsed < 5, f"饱和分析即时终止（{elapsed:.3f}s）")

    # 冻结回放：同标识同载荷 → 回放冻结结论
    code, obj = request("POST", base + "/api/analyze", NESTED)
    r3 = obj.get("result", {})
    ok &= check(code == 200 and r3.get("replayed") is True
                and r3.get("conclusion") == first_conclusion,
                "同标识同载荷重传→回放冻结结论", str(obj)[:200])

    # 改换载荷 → 明确拒绝 409
    changed = json.loads(json.dumps(NESTED))
    changed["procedures"][0]["nodes"][1] = {"id": "a1", "type": "return"}
    code, obj = request("POST", base + "/api/analyze", changed)
    ok &= check(code == 409 and "改换载荷被拒绝" in obj.get("conflict", ""),
                "同标识改换载荷→明确拒绝 409", str(obj)[:200])

    # 刷新后按审计标识读取相同证据
    code, obj = request("GET", base + "/api/evidence/SMOKE-NESTED")
    ok &= check(code == 200 and obj.get("conclusion") == first_conclusion
                and [s["kind"] for s in obj.get("steps", [])] == kinds,
                "按审计标识读取相同冻结证据（刷新持久）", str(obj)[:200])
    code, obj = request("GET", base + "/api/evidence/NO-SUCH")
    ok &= check(code == 404, "未知标识读取返回 404")

    # 一次性聚合多种校验错误
    bad_payload = {"audit_id": "", "root_entry": "nope", "procedures": [
        {"id": "p", "entry": "missing", "nodes": [
            {"id": "x", "type": "weird"},
            {"id": "x", "type": "jump", "next": "ghost"},
            {"id": "c", "type": "call", "target": "gone", "cont": "nocont"}]}]}
    code, obj = request("POST", base + "/api/analyze", bad_payload)
    joined = " ".join(obj.get("errors", []))
    ok &= check(code == 400, "聚合校验返回 400", str(obj)[:200])
    for token in ["audit_id", "类型无效", "悬空", "重复", "根入口错误"]:
        ok &= check(token in joined, f"一次指出：{token}", joined[:300])

    return ok


def main() -> int:
    print("=== rail-emergency-audit verify（一次运行后退出）===")
    built = build_check()
    tested = unit_tests()

    web_url = os.environ.get("WEB_URL", "").rstrip("/")
    proc = None
    if not web_url:
        # 本地模式：自己拉起真实服务（可配置端口）
        port = os.environ.get("PORT", "8099")
        env = dict(os.environ, HOST="127.0.0.1", PORT=str(port))
        proc = subprocess.Popen(
            [sys.executable, "-m", "app.server"],
            cwd=HERE, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        web_url = f"http://127.0.0.1:{port}"

    healthy = wait_healthy(web_url)
    if not healthy:
        print(f"\n  {FAIL} 服务在超时内未变为健康：{web_url}/health")
    smoked = healthy and http_smoke(web_url)

    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    total = len(results)
    passed = sum(1 for ok, _ in results if ok)
    print(f"\n=== 结果：{passed}/{total} 项通过 ===")
    return 0 if (built and tested and smoked) else 1


if __name__ == "__main__":
    sys.exit(main())
