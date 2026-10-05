# 问渠 wenqu v3.0 —— 可复用质量工程体系

> 问渠那得清如许，为有源头活水来。
> 一台电脑 → 一条命令 → 全套质量防线就位。

## 这是什么

从 ERP 生产线实战中沉淀的**完整质量工程体系**：20 规则铁门、影响面分析、
零返工验证管线、6 域资金守恒审计、TLA+/Z3 形式化证明、自愈守护、CI 哨兵、
部署前置门——打包成拷走即用的独立系统。

## 60 秒上手

```bash
# 1. 解压到任意电脑（macOS / Linux）
./install.sh                    # 安装到 ~/.wenqu 并注入 PATH

# 2. 配置（编辑 ~/.wenqu/env，填你的项目参数）
wenqu doctor                    # 体检：缺什么补什么

# 3. 在你的项目里
cd ~/my-project
wenqu init                      # 初始化（git 钩子 + 配置模板）
wenqu verify                    # 零返工验证管线
```

## 组件地图

| 层 | 命令 | 作用 |
|---|---|---|
| 快检 | `wenqu gate` | 20 规则铁门（账本/安全/规范，0.1s） |
| 验证 | `wenqu verify` | 铁门→影响面→定向测试→风险分 全管线 |
| 分析 | `wenqu blast` | 改动影响面（依赖图 BFS 找受波及测试） |
| 部署 | `wenqu preflight` | 五门（本地真值/血统镜像/指纹/形态/演练） |
| 形式化 | `wenqu tla` / `wenqu z3` | TLA+ 模型检查 / SMT 不变量证明 |
| 守恒 | `wenqu db triggers` | DB 三表守恒触发器+违约审计链 |
| 自愈 | `wenqu db selfheal` + `start` | 违约 10ms 自愈守护（LISTEN/NOTIFY） |
| 哨兵 | `wenqu cron` | CI 事件/守恒/证书 三哨兵 cron |
| 体检 | `wenqu doctor` | 全组件安装与配置状态 |

## 设计原则

1. **参数全部外置**——零硬编码 IP/域名/仓库名，一个 env 文件适配任何项目
2. **渐进启用**——不配 DB 参数就跳过 DB 组件，不配 webhook 就本地日志，绝不半死
3. **机器可判定**——每道防线 exit code 定生死，无「基本通过」
4. **账本思维**——质量发现记 jsonl 账本，风险分可回放、棘轮只进不退

## 目录

```
bin/       CLI 工具（12）：iron-gate / blast-radius / zero-rework / deploy-preflight ...
sentinels/ 哨兵（4）：CI 事件 / 守恒 / SSL 证书 / 周巡
daemons/   守护（3）：auto-merge / 守恒自愈 / CDC 流
db/        SQL（2）：守恒触发器 / 自愈链
ci/        CI 模板（2）：快层 + nightly
specs/     形式化：TLA+ 支付守恒 + Z3 五定理
templates/ 工单/README 模板
```

## 卸载

```bash
wenqu stop && wenqu uncron && rm -rf ~/.wenqu
```
