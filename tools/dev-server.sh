#!/usr/bin/env bash
# 开发模式服务：直接跑工作区源码，改完代码 ./tools/dev-server.sh restart 即生效。
# 不打包、不装 deb、不碰 systemd，端口与数据目录仍用生产那一套，联调地址不变。
#
#   ./tools/dev-server.sh start|stop|restart|status|log
#
# 可用环境变量覆盖：AKG_VENV / AKG_DATA_DIR / AKG_PORT / AKG_BIND / AKG_LOG / AKG_USER
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${AKG_VENV:-/opt/akg-dev-venv}"
DATA="${AKG_DATA_DIR:-/var/lib/agentkeyguard}"
PORT="${AKG_PORT:-7700}"
BIND="${AKG_BIND:-0.0.0.0}"
LOG="${AKG_LOG:-/tmp/akg-dev.log}"
PIDF="${AKG_PIDF:-/tmp/akg-dev.pid}"
USER_="${AKG_USER:-agentkeyguard}"

_py() { printf '%s/bin/python' "$VENV"; }

preflight() {
    [ -x "$(_py)" ] || { echo "缺少虚拟环境：$VENV（先跑 tools/dev-server.sh bootstrap）"; exit 1; }
    [ -f "$ROOT/src/agentkeyguard/__init__.py" ] || { echo "不是项目根：$ROOT"; exit 1; }
}

bootstrap() {
    if [ ! -x "$(_py)" ]; then
        echo "创建虚拟环境 $VENV …"
        mkdir -p "$(dirname "$VENV")"
        python3 -m venv "$VENV"
    fi
    "$VENV/bin/pip" install -q -r "$ROOT/requirements.txt"
    echo "依赖就绪：$("$(_py)" -c 'import cryptography,sys;print(sys.version.split()[0], cryptography.__version__)')"
}

# 进程特征串：只认本项目 venv 起的那个 python，避免误伤 systemd 实例
_pattern() { printf '%s/bin/python -m agentkeyguard serve --port %s' "$VENV" "$PORT"; }

running_pid() {
    local pid
    pid="$(pgrep -f "$(_pattern)" 2>/dev/null | head -1)"
    [ -n "$pid" ] && { echo "$pid"; return 0; }
    return 1
}

do_start() {
    preflight
    if pid="$(running_pid)"; then echo "已在运行 pid=$pid"; return 0; fi
    if [ -n "$(ss -tlnH "sport = :$PORT" 2>/dev/null)" ]; then
        echo "端口 $PORT 已被占用，先停掉 systemd 实例：systemctl stop agentkeyguard"
        ss -tlnp 2>/dev/null | grep ":$PORT " || true
        exit 1
    fi
    : > "$LOG"
    # 与生产同用户运行，避免 vault/audit 文件属主被改成 root
    local runner=()
    if [ "$(id -u)" = "0" ] && id "$USER_" >/dev/null 2>&1; then
        runner=(runuser -u "$USER_" --)
    fi
    ( cd "$ROOT" && \
      AGENTKEYGUARD_DATA_DIR="$DATA" PYTHONPATH="$ROOT/src" \
      nohup "${runner[@]}" "$(_py)" -m agentkeyguard serve --port "$PORT" --bind "$BIND" \
      >> "$LOG" 2>&1 & )
    sleep 3
    if pid="$(running_pid)"; then
        echo "$pid" > "$PIDF"
        echo "已启动 pid=$pid  port=$PORT  data=$DATA"
        echo "日志：$LOG"
    else
        echo "启动失败，末尾日志："; tail -20 "$LOG"; exit 1
    fi
}

do_stop() {
    if ! running_pid >/dev/null; then echo "未在运行"; rm -f "$PIDF"; return 0; fi
    local pids; pids="$(pgrep -f "$(_pattern)" 2>/dev/null | tr '\n' ' ')"
    pkill -f "$(_pattern)" 2>/dev/null
    for _ in $(seq 1 25); do
        running_pid >/dev/null || break
        sleep 0.2
    done
    running_pid >/dev/null && pkill -9 -f "$(_pattern)" 2>/dev/null && sleep 0.5
    echo "已停止（pid: ${pids% }）"
    rm -f "$PIDF"
}

do_status() {
    if pid="$(running_pid)"; then
        echo "运行中 pid=$pid  端口=$PORT  数据=$DATA"
        echo "代码版本：$(grep -m1 '^VERSION' "$ROOT/src/agentkeyguard/__init__.py")"
        echo "最近日志："; tail -5 "$LOG"
    else
        echo "未运行"
    fi
    echo "systemd 实例：$(systemctl is-active agentkeyguard 2>/dev/null)"
}

case "${1:-status}" in
    bootstrap) bootstrap ;;
    start)     do_start ;;
    stop)      do_stop ;;
    restart)   do_stop; do_start ;;
    status)    do_status ;;
    log)       tail -n "${2:-60}" "$LOG" ;;
    *) echo "用法：$0 {bootstrap|start|stop|restart|status|log}"; exit 1 ;;
esac
