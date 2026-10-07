# ADR-003：Trusted Runner

## 状态
已接受（2026-10-07，Codex 方案 §6.6/§11 冻结）

## 背景
当前任何脚本都可以自己报 exit 0/零发现——核心信任链断裂（FND-004）。

## 决策
建立独立 trusted runner 作为唯一证据生产者。

## 架构

```python
class TrustedRunner:
    def execute(self, argv: list[str], cwd: str, env_allowlist: set[str],
                timeout_s: int) -> Evidence:
        # 1. 以 argv 数组启动（禁 bash -c）
        # 2. subprocess.Popen + 实际 waitpid 捕获退出码
        # 3. 原始 stdout/stderr 复制进 CAS + fsync
        # 4. O_NOFOLLOW/lstat/realpath 拒绝 symlink
        # 5. 写 manifest（含全部身份绑定字段）
        # 6. 调用者不得填写 actual_exit_code 或总 findings
```

## 关键约束

1. **不可伪造退出码**：runner 是唯一可以记录 actual_exit_code 的组件
2. **不可伪造证据**：原始输出直接进 CAS，不经调用者
3. **symlink 拒绝**：O_NOFOLLOW + lstat 检查
4. **源不可变**：基于目标 commit 的不可变源快照执行
5. **资源限额**：CPU/内存/进程数/输出大小/文件大小限制
6. **进程组终止**：timeout 后 kill 整个 process group/cgroup

## 实现路径

第一阶段：Python subprocess + fsync + O_NOFOLLOW（本机可跑）
第二阶段：macOS sandbox-exec 隔离
第三阶段：ephemeral VM/container（如果需要）

## 与现有件的关系
- 现有 JSONL 中的 exit_code/findings 不迁移为可信——标记为 legacy_self_reported
- 新跑的每条证据必须来自 trusted runner
- verify-convergence 只消费 trusted runner 签发的证据
