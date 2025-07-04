#!/bin/bash
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 卸载脚本
"""

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 确认卸载
confirm_uninstall() {
    echo "=================================="
    echo "  分布式Fail2ban系统卸载脚本"
    echo "=================================="
    echo
    
    log_warning "此操作将完全移除分布式Fail2ban系统！"
    log_warning "包括:"
    echo "  - 所有服务和配置文件"
    echo "  - 用户数据和日志"
    echo "  - 系统用户账户"
    echo "  - Python依赖包"
    echo
    
    read -p "确定要继续吗？[y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "取消卸载"
        exit 0
    fi
    
    read -p "请再次确认，这将删除所有数据！[yes/no]: " confirm2
    if [[ "$confirm2" != "yes" ]]; then
        log_info "取消卸载"
        exit 0
    fi
}

# 停止服务
stop_services() {
    log_info "停止服务..."
    
    # 停止分布式Fail2ban服务
    services=("fail2ban-central" "fail2ban-agent" "fail2ban-executor" "fail2ban-web")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_info "停止服务: $service"
            systemctl stop "$service"
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log_info "禁用服务: $service"
            systemctl disable "$service"
        fi
    done
    
    log_success "服务停止完成"
}

# 删除systemd服务文件
remove_services() {
    log_info "删除systemd服务文件..."
    
    service_files=(
        "/etc/systemd/system/fail2ban-central.service"
        "/etc/systemd/system/fail2ban-agent.service"
        "/etc/systemd/system/fail2ban-executor.service"
        "/etc/systemd/system/fail2ban-web.service"
    )
    
    for file in "${service_files[@]}"; do
        if [[ -f "$file" ]]; then
            log_info "删除服务文件: $file"
            rm -f "$file"
        fi
    done
    
    # 重新加载systemd
    systemctl daemon-reload
    
    log_success "systemd服务文件删除完成"
}

# 删除文件和目录
remove_files() {
    log_info "删除文件和目录..."
    
    # 删除项目目录
    if [[ -d "/opt/fail2ban" ]]; then
        log_info "删除项目目录: /opt/fail2ban"
        rm -rf /opt/fail2ban
    fi
    
    # 删除配置目录
    if [[ -d "/etc/fail2ban-distributed" ]]; then
        log_info "删除配置目录: /etc/fail2ban-distributed"
        rm -rf /etc/fail2ban-distributed
    fi
    
    # 删除日志目录
    if [[ -d "/var/log/fail2ban-distributed" ]]; then
        log_info "删除日志目录: /var/log/fail2ban-distributed"
        rm -rf /var/log/fail2ban-distributed
    fi
    
    # 删除数据目录
    if [[ -d "/var/lib/fail2ban-distributed" ]]; then
        log_info "删除数据目录: /var/lib/fail2ban-distributed"
        rm -rf /var/lib/fail2ban-distributed
    fi
    
    # 删除Nginx配置
    if [[ -f "/etc/nginx/conf.d/fail2ban-log.conf" ]]; then
        log_info "删除Nginx配置: /etc/nginx/conf.d/fail2ban-log.conf"
        rm -f /etc/nginx/conf.d/fail2ban-log.conf
    fi
    
    log_success "文件和目录删除完成"
}

# 删除系统用户
remove_user() {
    log_info "删除系统用户..."
    
    if id "fail2ban" &>/dev/null; then
        log_info "删除用户: fail2ban"
        userdel -r fail2ban 2>/dev/null || true
        log_success "用户删除完成"
    else
        log_info "用户fail2ban不存在"
    fi
}

# 卸载Python依赖
remove_python_deps() {
    log_info "卸载Python依赖..."
    
    # 读取requirements.txt并卸载包
    if [[ -f "requirements.txt" ]]; then
        log_info "卸载Python包..."
        python3 -m pip uninstall -y -r requirements.txt 2>/dev/null || true
    fi
    
    # 手动卸载主要包
    packages=(
        "fastapi"
        "uvicorn"
        "websockets"
        "redis"
        "pymongo"
        "watchdog"
        "requests"
        "pyyaml"
        "jinja2"
        "python-multipart"
    )
    
    for package in "${packages[@]}"; do
        python3 -m pip uninstall -y "$package" 2>/dev/null || true
    done
    
    log_success "Python依赖卸载完成"
}

# 清理数据库数据
clean_databases() {
    log_info "清理数据库数据..."
    
    # 清理Redis数据
    if command -v redis-cli &> /dev/null; then
        log_info "清理Redis数据..."
        redis-cli FLUSHDB 2>/dev/null || true
    fi
    
    # 清理MongoDB数据
    if command -v mongo &> /dev/null; then
        log_info "清理MongoDB数据..."
        mongo fail2ban --eval "db.dropDatabase()" 2>/dev/null || true
    fi
    
    log_success "数据库清理完成"
}

# 恢复防火墙设置
restore_firewall() {
    log_info "恢复防火墙设置..."
    
    if command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL firewalld
        firewall-cmd --permanent --remove-port=8080/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=5000/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=5001/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    elif command -v ufw &> /dev/null; then
        # Ubuntu ufw
        ufw delete allow 8080/tcp 2>/dev/null || true
        ufw delete allow 5000/tcp 2>/dev/null || true
        ufw delete allow 5001/tcp 2>/dev/null || true
    fi
    
    log_success "防火墙设置恢复完成"
}

# 恢复Nginx配置
restore_nginx() {
    log_info "恢复Nginx配置..."
    
    # 恢复备份的配置文件
    if [[ -f "/etc/nginx/nginx.conf.bak" ]]; then
        log_info "恢复Nginx配置备份"
        cp /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
        rm -f /etc/nginx/nginx.conf.bak
        
        # 重启Nginx
        systemctl restart nginx 2>/dev/null || true
    fi
    
    log_success "Nginx配置恢复完成"
}

# 询问是否卸载基础依赖
remove_base_deps() {
    echo
    read -p "是否卸载基础依赖包（Nginx, Fail2ban, Redis, MongoDB）？[y/N]: " remove_deps
    
    if [[ "$remove_deps" =~ ^[Yy]$ ]]; then
        log_info "卸载基础依赖包..."
        
        # 检测操作系统
        if [[ -f /etc/redhat-release ]]; then
            # CentOS
            yum remove -y nginx fail2ban redis mongodb-server 2>/dev/null || true
        elif [[ -f /etc/lsb-release ]]; then
            # Ubuntu
            apt-get remove -y nginx fail2ban redis-server mongodb 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
        fi
        
        log_success "基础依赖包卸载完成"
    else
        log_info "保留基础依赖包"
    fi
}

# 显示卸载结果
show_result() {
    log_success "=== 卸载完成 ==="
    echo
    
    log_info "已删除的内容:"
    echo "  ✓ 所有服务和配置文件"
    echo "  ✓ 项目文件和目录"
    echo "  ✓ 系统用户账户"
    echo "  ✓ Python依赖包"
    echo "  ✓ 数据库数据"
    echo "  ✓ 防火墙规则"
    echo
    
    log_info "保留的内容:"
    echo "  - 系统日志（/var/log/messages, /var/log/syslog等）"
    echo "  - 原始Fail2ban配置"
    echo "  - 原始Nginx配置"
    echo
    
    log_warning "建议执行以下操作:"
    echo "  1. 检查系统日志确认无异常"
    echo "  2. 重启相关服务确保正常运行"
    echo "  3. 清理可能残留的临时文件"
    echo
    
    log_success "分布式Fail2ban系统已完全卸载！"
}

# 主函数
main() {
    check_root
    confirm_uninstall
    
    log_info "开始卸载..."
    
    stop_services
    remove_services
    clean_databases
    remove_files
    remove_user
    remove_python_deps
    restore_firewall
    restore_nginx
    remove_base_deps
    
    show_result
}

# 运行主函数
main "$@"