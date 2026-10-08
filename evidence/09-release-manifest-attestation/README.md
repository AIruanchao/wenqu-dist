# 09-release-manifest-attestation — 发布清单与签名证据

## 证据类型

- Release manifest（§16.2）：制品清单、逐项 SHA256、build identity（在哪个 commit/环境构建）；
- 签名/attestation（§21.4）：签名公钥指纹、验签记录、key 轮换台账；
- runtime/source 身份对账：部署后运行体 hash 与 manifest 逐项一致（消灭 FND-008 热补漂移）；
- 安装器行为证据：不再原地覆盖、doctor 失败即失败（FND-009）。

对应 §16（W7A/W7B 制品与原子部署）。

## 关联测试 ID

REL-01～03、DEP-03～05、RB-01（兼容性证据侧）、CAP-01。

## 当前状态（2026-10-08 建档时点）

**PARTIAL——有哈希清单链（v1.0.6 → v3.6.3 共 25 份 SHA256 文件），但无 manifest 结构、无签名、
无 build identity 绑定**：

| 工件 | 状态 |
|---|---|
| `SHA256-v*.txt`（v1.0.6～v3.6.3，25 份） | 存在于仓根；v3.6.3 清单自身 SHA256 2e7a2b35…（2026-10-08 计算） |
| `system/wenqu_core/deploy_framework.py`（原子部署骨架） | 存在；P0-6+7 修复 exec bit/首败 current link（be50cb8） |
| `system/install.sh` 安装行为证据 | acceptance.sh P0 节覆盖「升级覆盖旧 writer 为安全 stub」（绿），但 doctor 吞错修复的完整正反例未落档 |
| 签名/attestation | **无**（DEP-04 全空） |
| build identity / runtime 对账 | **无**（外部 reaudit 的 runtime-source-hashes/diff 未固化） |

## 填写规则

1. manifest 必须机器生成，含生成 argv、commit、环境；人工编辑即作废。
2. 每次发布后追加 runtime 对账记录（部署体 hash vs manifest），任何漂移即事件。
3. 密钥类证据只存公钥指纹与验签输出，严禁入档私钥。
