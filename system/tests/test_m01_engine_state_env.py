# -*- coding: utf-8 -*-
"""M-01/M-01b 回归保护：WENQU_ERP_ENGINE_STATE 覆写 + stale 标注双通道。

覆盖（对抗审查发现 3 补齐——此前四态实测未入仓，新分支零已提交保护）：
1. env 覆写 engine_state_path；未设/空串回落默认；显式参数优先于 env
2. 快照 mtime>86400s：ScannerReport.note 标注（不改变判定）
3. 新鲜快照：无标注
4. 生产链可见性：station_result.tool.warnings 持久化通道（M-01b——
   dispatch 只透传 station_result，信封 notes 被丢弃）
5. 阈值严格性（>86400）
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wenqu_core.station2_static import (  # noqa: E402
    DEFAULT_ENGINE_STATE_PATH,
    EngineFiveTypesScanner,
    Station2Static,
)

_IDENT = {
    "commit_sha": "a3b96a65aee8769bc47829d211e0dfdbe171ff4e",
    "data_config_hash": "x", "environment": "local",
    "project_id": "wenqu-dist", "ruleset_hash": "y", "scope_hash": "z",
}
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _make_state(path, mtime=None):
    path.write_text(json.dumps(
        {"queue": [{"slug": "A", "status": "MERGED 收口"}],
         "cursor_inflight": None}), encoding="utf-8")
    if mtime is not None:
        os.utime(str(path), (mtime, mtime))


class TestEngineStateEnvOverride(unittest.TestCase):
    def test_env_override_and_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "erp-engine-state.json"
            _make_state(fake)
            os.environ["WENQU_ERP_ENGINE_STATE"] = str(fake)
            try:
                s = EngineFiveTypesScanner(
                    run_id="t", identity=_IDENT, repo_dir=_REPO, runner=None)
                self.assertEqual(str(s._state_path), str(fake))
                s2 = Station2Static(
                    "t2", identity=_IDENT, repo_dir=_REPO, scanners=["engine"])
                eng = s2._scanner_impls["engine"]
                self.assertEqual(str(eng._state_path), str(fake))
            finally:
                del os.environ["WENQU_ERP_ENGINE_STATE"]
        s3 = EngineFiveTypesScanner(
            run_id="t3", identity=_IDENT, repo_dir=_REPO, runner=None)
        self.assertEqual(str(s3._state_path), str(DEFAULT_ENGINE_STATE_PATH))

    def test_explicit_param_beats_env(self):
        with tempfile.TemporaryDirectory() as td:
            a, b = Path(td) / "a.json", Path(td) / "b.json"
            _make_state(a)
            _make_state(b)
            os.environ["WENQU_ERP_ENGINE_STATE"] = str(a)
            try:
                s = EngineFiveTypesScanner(
                    engine_state_path=str(b), run_id="t",
                    identity=_IDENT, repo_dir=_REPO, runner=None)
                self.assertEqual(str(s._state_path), str(b))
            finally:
                del os.environ["WENQU_ERP_ENGINE_STATE"]

    def test_empty_env_string_falls_back_to_default(self):
        old = os.environ.get("WENQU_ERP_ENGINE_STATE")
        os.environ["WENQU_ERP_ENGINE_STATE"] = ""
        try:
            s = EngineFiveTypesScanner(
                run_id="t", identity=_IDENT, repo_dir=_REPO, runner=None)
            self.assertEqual(str(s._state_path), str(DEFAULT_ENGINE_STATE_PATH))
        finally:
            if old is None:
                del os.environ["WENQU_ERP_ENGINE_STATE"]
            else:
                os.environ["WENQU_ERP_ENGINE_STATE"] = old


class TestStaleAnnotation(unittest.TestCase):
    def _scanner(self, path):
        return EngineFiveTypesScanner(
            engine_state_path=str(path), run_id="t",
            identity=_IDENT, repo_dir=_REPO, runner=None)

    def test_stale_note_and_fresh_no_note(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "s.json"
            _make_state(fake, mtime=time.time() - 3 * 86400)
            rep = self._scanner(fake)._scan_via_state_file()
            self.assertIn("stale", rep.note)
            _make_state(fake, mtime=time.time())
            rep2 = self._scanner(fake)._scan_via_state_file()
            self.assertNotIn("stale", rep2.note)
            # 判定不被 stale 改变
            self.assertEqual(rep.result.get("policy_verdict"),
                             rep2.result.get("policy_verdict"))

    def test_threshold_strict(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "s.json"
            _make_state(fake, mtime=time.time() - 86398)
            self.assertNotIn("stale", self._scanner(fake)._scan_via_state_file().note)
            _make_state(fake, mtime=time.time() - 86405)
            self.assertIn("stale", self._scanner(fake)._scan_via_state_file().note)


class TestToolWarningsChannel(unittest.TestCase):
    def test_station_result_carries_stale_warning(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "s.json"
            _make_state(fake, mtime=time.time() - 3 * 86400)
            os.environ["WENQU_ERP_ENGINE_STATE"] = str(fake)
            try:
                sr = Station2Static(
                    "t", identity=_IDENT, repo_dir=_REPO,
                    scanners=["engine"]).scan()["station_result"]
            finally:
                del os.environ["WENQU_ERP_ENGINE_STATE"]
            tool = sr.get("tool", {})
            warns = tool.get("warnings")
            self.assertTrue(
                warns and any("stale" in w for w in warns),
                f"tool.warnings 应携带 stale 标注，实际 tool={tool}")
            # 新鲜态不带 warnings 键
            _make_state(fake, mtime=time.time())
            os.environ["WENQU_ERP_ENGINE_STATE"] = str(fake)
            try:
                sr2 = Station2Static(
                    "t2", identity=_IDENT, repo_dir=_REPO,
                    scanners=["engine"]).scan()["station_result"]
            finally:
                del os.environ["WENQU_ERP_ENGINE_STATE"]
            self.assertFalse(sr2.get("tool", {}).get("warnings"))


if __name__ == "__main__":
    unittest.main()
