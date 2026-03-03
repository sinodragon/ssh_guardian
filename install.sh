#!/bin/bash
# =============================================================================
# SSH Guardian 一键部署脚本
# 在 Debian 10 服务器上执行：bash install.sh
# =============================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── 检查 root ────────────────────────────────────────────────────────────────
[ "$EUID" -eq 0 ] || error "请以 root 权限运行此脚本"

# ── 检查依赖 ─────────────────────────────────────────────────────────────────
info "检查系统依赖..."
command -v ufw  >/dev/null 2>&1 || error "ufw 未安装，请先执行: apt install ufw"
command -v cargo >/dev/null 2>&1 || {
    warn "未检测到 Rust 工具链，正在安装..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
}

# ── 编译 ─────────────────────────────────────────────────────────────────────
info "编译 ssh_guardian（release 模式）..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release
info "编译完成：$(ls -lh target/release/ssh_guardian)"

# ── 安装二进制 ───────────────────────────────────────────────────────────────
info "安装二进制文件到 /usr/local/bin/..."
cp target/release/ssh_guardian /usr/local/bin/ssh_guardian
chmod 755 /usr/local/bin/ssh_guardian

# ── 创建目录 ─────────────────────────────────────────────────────────────────
info "创建配置和数据目录..."
mkdir -p /etc/ssh_guardian
mkdir -p /var/lib/ssh_guardian

# ── 安装配置（不覆盖已有配置）────────────────────────────────────────────────
if [ ! -f /etc/ssh_guardian/config.json ]; then
    cp "$SCRIPT_DIR/config.json" /etc/ssh_guardian/config.json
    info "已安装默认配置到 /etc/ssh_guardian/config.json"
    warn "⚠  请编辑配置文件，将你的管理IP加入 whitelist！"
    warn "   nano /etc/ssh_guardian/config.json"
else
    info "配置文件已存在，跳过覆盖"
fi

# ── 安装 systemd 服务 ─────────────────────────────────────────────────────────
info "安装 systemd 服务..."
cp "$SCRIPT_DIR/ssh_guardian.service" /etc/systemd/system/ssh_guardian.service
systemctl daemon-reload

# ── 检查 UFW 状态 ─────────────────────────────────────────────────────────────
UFW_STATUS=$(ufw status | head -1)
if echo "$UFW_STATUS" | grep -q "inactive"; then
    warn "UFW 当前未启用。如需启用请执行: ufw enable"
    warn "注意：启用 UFW 前请确保已开放 SSH 端口：ufw allow ssh"
else
    info "UFW 状态: $UFW_STATUS"
fi

# ── 启用并启动服务 ────────────────────────────────────────────────────────────
info "启用并启动 ssh_guardian 服务..."
systemctl enable ssh_guardian
systemctl start  ssh_guardian

sleep 2
STATUS=$(systemctl is-active ssh_guardian)
if [ "$STATUS" = "active" ]; then
    info "✓ ssh_guardian 服务运行正常"
else
    error "服务启动失败，请检查日志：journalctl -u ssh_guardian -n 50"
fi

# ── 完成摘要 ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo -e "${GREEN}  SSH Guardian 部署完成！${NC}"
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo ""
echo "  配置文件   : /etc/ssh_guardian/config.json"
echo "  日志文件   : /var/log/ssh_guardian.log"
echo "  状态数据库 : /var/lib/ssh_guardian/state.json"
echo ""
echo "  常用命令："
echo "    systemctl status  ssh_guardian      # 服务状态"
echo "    systemctl restart ssh_guardian      # 重启服务"
echo "    tail -f /var/log/ssh_guardian.log   # 实时查看日志"
echo "    journalctl -u ssh_guardian -f       # journald 日志"
echo "    ufw status                          # 查看当前封禁规则"
echo ""
