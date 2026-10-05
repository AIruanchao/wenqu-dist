#!/usr/bin/env bash
# wenqu-env.sh —— 中央配置加载器（v3，bash 3.2 兼容）
# 优先级：环境变量 > 项目 .wenqu.env > 全局 $WENQU_HOME/env > 内置默认(占位符)
for _f in "${WENQU_HOME:-$HOME/.wenqu}/env" "$PWD/.wenqu.env"; do
  [ -f "$_f" ] && . "$_f"
done
unset _f
# POSIX 参数化默认值（set -u 安全）
: "${WENQU_REPO:=OWNER/REPO}"
: "${WENQU_REPO_DIR:=$HOME/my-project}"
: "${WENQU_RELAY_HOST:=}"
: "${WENQU_RELAY_LOCAL:=$HOME/my-project-relay}"
: "${WENQU_DB_SSH:=}"
: "${WENQU_DB_NAME:=mydb}"
: "${WENQU_DB_DSN:=}"
: "${WENQU_ALERT_WEBHOOK:=}"
: "${WENQU_CERT_DOMAIN:=}"
: "${WENQU_DEPLOY_DIR:=/opt/myapp}"
: "${WENQU_LINEAGE_GIT:=/opt/lineage/repo.git}"
export WENQU_REPO WENQU_REPO_DIR WENQU_RELAY_HOST WENQU_RELAY_LOCAL \
       WENQU_DB_SSH WENQU_DB_NAME WENQU_DB_DSN WENQU_ALERT_WEBHOOK \
       WENQU_CERT_DOMAIN WENQU_DEPLOY_DIR WENQU_LINEAGE_GIT
