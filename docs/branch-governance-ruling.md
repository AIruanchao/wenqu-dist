# 分支治理裁定（W11-12 / R10 分支治理项）

## 裁定（超哥 2026-10-11，2-B）

单主体项目：required review（第二人评审）与 required signatures（签名提交）
在单人账号体系下**结构性不可达**——本仓无第二可信 GitHub 身份。

处置：
- W3 的 review/signature/ruleset 2 分按结构性不适用计（不视为可修复缺陷）
- 验收总分上限=94/96（工程面）+4（时钟 W9/W10）=**98/100**
- 补偿性控制（已落地）：strict required checks 双平台+禁 force/delete+PR 正门
  +roots 外部授权+Ed25519 裁定验签+registry 异钥语义根+双 pin 事务
  +漂移哨兵熔断——单主体下的多信号交叉替代双人评审的风险面
- 若未来引入第二身份：gh api 补 required_pull_requestreviews +
  required_signatures 后此裁定作废，2 分恢复可争
