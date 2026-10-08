# 09-release-manifest-attestation — 发布清单与签名证据

## 证据类型

- Release manifest（§16.2）：制品清单、逐项 SHA256、build identity（在哪个 commit/环境构建）；
- 签名/attestation（§21.4）：签名公钥指纹、验签记录、key 轮换台账；
- runtime/source 身份对账：部署后运行体 hash 与 manifest 逐项一致（消灭 FND-008 热补漂移）；
- 安装器行为证据：不再原地覆盖、doctor 失败即失败（FND-009）。

对应 §16（W7A/W7B 制品与原子部署）。

## 关联测试 ID

REL-01～03、DEP-03～05、RB-01（兼容性证据侧）、CAP-01。

## 当前状态（2026-10-08 签名/SBOM 能力落档）

**PARTIAL→进行中——哈希清单链（v1.0.6 → v3.6.3 共 25 份 SHA256 文件）之上，
本日新增独立打包工具四件套（manifest+签名+SBOM+verify）；部署侧接线（DEP-04
运行时验签）由并行工作流在 `system/wenqu_core/deploy_framework.py` 推进，两轨独立。**

| 工件 | 状态 |
|---|---|
| `SHA256-v*.txt`（v1.0.6～v3.6.3，25 份） | 存在于仓根；v3.6.3 清单自身 SHA256 2e7a2b35…（2026-10-08 计算） |
| `system/wenqu_core/deploy_framework.py`（原子部署骨架） | 存在；P0-6+7 修复 exec bit/首败 current link（be50cb8） |
| `system/install.sh` 安装行为证据 | acceptance.sh P0 节覆盖「升级覆盖旧 writer 为安全 stub」（绿），但 doctor 吞错修复的完整正反例未落档 |
| 签名/attestation（**2026-10-08 新增，工具侧**） | `tools/release_attest.py` v1.0.0（纯标准库）：build/sign/sbom/verify 四命令；detached HMAC-SHA256（wenqu_core.approval_keys keyring 只读复用，含 key_id、revoked fail-closed）；SPDX 2.3 SBOM；verify 对 tar+manifest+sig+sbom 四件套对账，任一不符 exit 1 |
| DEP-04（部署侧运行时验签） | **并行工作流进行中**（deploy_framework.py 签名字段）——工具侧契约已冻结可对接：manifest schema `wenqu-release-manifest/1`、sig schema `wenqu-release-sig/1` |
| build identity / runtime 对账 | 工具侧已含（manifest 带 commit/argv/builder/时间戳）；外部 reaudit 的 runtime-source-hashes/diff 未固化 |

### 本目录运行记录

- `release-attest-run-1620c7c.json` —— HEAD 1620c7c 全链实跑登记（build+sign+sbom+verify 全绿，含四件套 sha256）；
- `release-attest-run-1620c7c.log` —— 全链控制台日志（keyring 路径与 key_id 可见，**无 secret**）；
- `verify-report-1620c7c.json` —— verify 机器可读报告（六检查项全 PASS）。

### 四件套产物（dist/，2026-10-08）

| 文件 | sha256 |
|---|---|
| `dist/wenqu-dist-1620c7c.tar.gz`（642 文件，7,095,163 B） | `e2243329c33eb003b40726cea41bc17410d7ecfc1797ba0a59fe84561c4c2607` |
| `dist/wenqu-dist-1620c7c.manifest.json` | `6fd61cfef62d80a9dd87b0930065df6c94713d9f476678af6c08ab687eacd560` |
| `dist/wenqu-dist-1620c7c.release.sig`（key_release_w6p1f） | `8858b211594944bd3f129878cabef4f0adb7e68fdd63455fe3ae7bdf7dc138c3` |
| `dist/wenqu-dist-1620c7c.sbom.spdx.json`（SPDX 2.3，642 files，deps=0） | `76e765b25513b8fe630dd29cf5251903a18543f88b090cf24d12927aa583c57e` |

复验：`python3 tools/release_attest.py verify --manifest dist/wenqu-dist-1620c7c.manifest.json --keyring ~/.wenqu-dist-release/release-keyring.json`
测试：`python3 system/tests/test_release_attest.py`（8 PASS：篡改 tar 一字节必拒／重打包+自洽改 manifest 被签名拦截／换 key 必拒／SBOM 字段完整性+篡改必拒／manifest+sig 篡改必拒／rotated 不得签发+revoked 验签即拒／确定性构建／verify 报告工件）。

### 诚实边界（§21.4）

- **HMAC 对称签名非非否认**：与审批体系同一信任根（wenqu_core.approval_keys），
  提供 tamper-evident／防伪造；持有 secret 者可重签——未建立独立 release signer
  （CI/独立 broker 持钥、被测运行体不可及）前，只可宣称 hash drift detection /
  tamper-evident，不得声称「签名证明来源」。
- 签发 key `key_release_w6p1f` 为本机 dev 根（`~/.wenqu-dist-release/`，0600，
  仓外物理隔离）；生产发布必须轮换为隔离环境持有的 key。
- SBOM 依赖信息只从归档内自述文件提取（无网络、无猜测）：本仓归档内无
  requirements/package.json 等清单，按 README 自述（stdlib-only）记零第三方依赖。
- `dist/` 四件套中的 tar 含 HEAD 树内既有的 f2b8fc3 候选包（commit 树自带）。

## 填写规则

1. manifest 必须机器生成，含生成 argv、commit、环境；人工编辑即作废。
2. 每次发布后追加 runtime 对账记录（部署体 hash vs manifest），任何漂移即事件。
3. 密钥类证据只存公钥指纹与验签输出，严禁入档私钥。（HMAC 为对称密钥：
   证据只登记 key_id、keyring 路径与验签结果，secret 绝不落档。）
