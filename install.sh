#!/bin/bash
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 安装脚本
支持CentOS 7/8和Ubuntu 18.04/20.04/22.04
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

# 检测操作系统
detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
        if grep -q "CentOS Linux release 7" /etc/redhat-release; then
            OS_VERSION="7"
        elif grep -q "CentOS Linux release 8" /etc/redhat-release; then
            OS_VERSION="8"
        else
            log_error "不支持的CentOS版本"
            exit 1
        fi
    elif [[ -f /etc/lsb-release ]]; then
        OS="ubuntu"
        OS_VERSION=$(lsb_release -rs)
        if [[ ! "$OS_VERSION" =~ ^(18.04|20.04|22.04)$ ]]; then
            log_error "不支持的Ubuntu版本: $OS_VERSION"
            exit 1
        fi
    else
        log_error "不支持的操作系统"
        exit 1
    fi
    
    log_info "检测到操作系统: $OS $OS_VERSION"
}

# 安装基础依赖
install_dependencies() {
    log_info "安装基础依赖..."
    
    if [[ "$OS" == "centos" ]]; then
        # CentOS
        yum update -y
        yum install -y epel-release
        yum install -y python3 python3-pip git wget curl nginx fail2ban redis mongodb-server
        
        # 启用服务
        systemctl enable nginx
        systemctl enable fail2ban
        systemctl enable redis
        systemctl enable mongod
        
    elif [[ "$OS" == "ubuntu" ]]; then
        # Ubuntu
        apt-get update
        apt-get install -y python3 python3-pip git wget curl nginx fail2ban redis-server mongodb
        
        # 启用服务
        systemctl enable nginx
        systemctl enable fail2ban
        systemctl enable redis-server
        systemctl enable mongodb
    fi
    
    log_success "基础依赖安装完成"
}

# 安装Python依赖
install_python_deps() {
    log_info "安装Python依赖..."
    
    # 升级pip
    python3 -m pip install --upgrade pip
    
    # 安装项目依赖
    if [[ -f "requirements.txt" ]]; then
        python3 -m pip install -r requirements.txt
    else
        log_error "requirements.txt文件不存在"
        exit 1
    fi
    
    log_success "Python依赖安装完成"
}

# 创建系统用户
create_user() {
    log_info "创建系统用户..."
    
    if ! id "fail2ban" &>/dev/null; then
        useradd -r -s /bin/false -d /opt/fail2ban fail2ban
        log_success "用户fail2ban创建成功"
    else
        log_info "用户fail2ban已存在"
    fi
}

# 创建目录结构
create_directories() {
    log_info "创建目录结构..."
    
    mkdir -p /opt/fail2ban
    mkdir -p /etc/fail2ban-distributed
    mkdir -p /var/log/fail2ban-distributed
    mkdir -p /var/lib/fail2ban-distributed
    
    # 设置权限
    chown -R fail2ban:fail2ban /opt/fail2ban
    chown -R fail2ban:fail2ban /var/log/fail2ban-distributed
    chown -R fail2ban:fail2ban /var/lib/fail2ban-distributed
    
    log_success "目录结构创建完成"
}

# 复制项目文件
copy_files() {
    log_info "复制项目文件..."
    
    # 复制所有Python文件
    cp -r ./* /opt/fail2ban/
    
    # 复制配置文件
    if [[ -f "config.example.yaml" ]]; then
        cp config.example.yaml /etc/fail2ban-distributed/config.yaml
    fi
    
    # 设置权限
    chown -R fail2ban:fail2ban /opt/fail2ban
    chmod +x /opt/fail2ban/main.py
    
    log_success "项目文件复制完成"
}

# 配置systemd服务
configure_services() {
    log_info "配置systemd服务..."
    
    # 中央控制节点服务
    cat > /etc/systemd/system/fail2ban-central.service << EOF
[Unit]
Description=Fail2ban Distributed Central Server
After=network.target redis.service mongodb.service
Requires=redis.service mongodb.service

[Service]
Type=simple
User=fail2ban
Group=fail2ban
WorkingDirectory=/opt/fail2ban
ExecStart=/usr/bin/python3 /opt/fail2ban/main.py --mode central --config /etc/fail2ban-distributed/config.yaml
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/fail2ban

[Install]
WantedBy=multi-user.target
EOF

    # 日志收集代理服务
    cat > /etc/systemd/system/fail2ban-agent.service << EOF
[Unit]
Description=Fail2ban Distributed Log Agent
After=network.target nginx.service
Requires=nginx.service

[Service]
Type=simple
User=fail2ban
Group=fail2ban
WorkingDirectory=/opt/fail2ban
ExecStart=/usr/bin/python3 /opt/fail2ban/main.py --mode agent --config /etc/fail2ban-distributed/config.yaml
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/fail2ban

[Install]
WantedBy=multi-user.target
EOF

    # 执行节点服务
    cat > /etc/systemd/system/fail2ban-executor.service << EOF
[Unit]
Description=Fail2ban Distributed Executor
After=network.target fail2ban.service
Requires=fail2ban.service

[Service]
Type=simple
User=fail2ban
Group=fail2ban
WorkingDirectory=/opt/fail2ban
ExecStart=/usr/bin/python3 /opt/fail2ban/main.py --mode executor --config /etc/fail2ban-distributed/config.yaml
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/fail2ban

[Install]
WantedBy=multi-user.target
EOF

    # Web仪表板服务
    cat > /etc/systemd/system/fail2ban-web.service << EOF
[Unit]
Description=Fail2ban Distributed Web Dashboard
After=network.target

[Service]
Type=simple
User=fail2ban
Group=fail2ban
WorkingDirectory=/opt/fail2ban
ExecStart=/usr/bin/python3 -m uvicorn web.dashboard:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/fail2ban

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载systemd
    systemctl daemon-reload
    
    log_success "systemd服务配置完成"
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    if command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL firewalld
        firewall-cmd --permanent --add-port=8080/tcp  # Web界面
        firewall-cmd --permanent --add-port=5000/tcp  # API
        firewall-cmd --permanent --add-port=5001/tcp  # WebSocket
        firewall-cmd --reload
    elif command -v ufw &> /dev/null; then
        # Ubuntu ufw
        ufw allow 8080/tcp
        ufw allow 5000/tcp
        ufw allow 5001/tcp
    fi
    
    log_success "防火墙配置完成"
}

# 配置Nginx日志格式
configure_nginx() {
    log_info "配置Nginx日志格式..."
    
    # 备份原配置
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    
    # 添加自定义日志格式
    cat > /etc/nginx/conf.d/fail2ban-log.conf << 'EOF'
# 分布式Fail2ban系统日志格式
log_format fail2ban_format '$remote_addr - $remote_user [$time_local] '
                          '"$request" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent" '
                          '$request_time $upstream_response_time';

# 在server块中使用:
# access_log /var/log/nginx/access.log fail2ban_format;
EOF
    
    # 重启Nginx
    systemctl restart nginx
    
    log_success "Nginx配置完成"
}

# 生成配置文件
generate_config() {
    log_info "生成配置文件..."
    
    # 生成随机密钥
    API_KEY=$(openssl rand -hex 32)
    SECRET_KEY=$(openssl rand -hex 32)
    
    # 获取本机IP
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    cat > /etc/fail2ban-distributed/config.yaml << EOF
# 分布式Fail2ban系统配置文件
# 安装时间: $(date)

# 系统基础设置
system:
  mode: "central"  # central, agent, executor, all
  node_id: "$(hostname)-$(date +%s)"
  log_level: "INFO"
  log_file: "/var/log/fail2ban-distributed/system.log"

# 中央控制节点配置
central:
  api:
    host: "0.0.0.0"
    port: 5000
    api_key: "$API_KEY"
  
  websocket:
    host: "0.0.0.0"
    port: 5001
  
  database:
    redis:
      host: "localhost"
      port: 6379
      db: 0
      password: ""
    
    mongodb:
      host: "localhost"
      port: 27017
      database: "fail2ban"
      username: ""
      password: ""

# 日志收集代理配置
agent:
  central_server:
    host: "$LOCAL_IP"
    port: 5000
    api_key: "$API_KEY"
  
  log_paths:
    - "/var/log/nginx/access.log"
    - "/var/log/nginx/error.log"
  
  sender:
    batch_size: 100
    send_interval: 10
    retry_times: 3
    retry_interval: 5

# 封禁执行节点配置
executor:
  central_server:
    host: "$LOCAL_IP"
    port: 5001
    api_key: "$API_KEY"
  
  fail2ban:
    config_path: "/etc/fail2ban"
    jail_name: "distributed-ban"
    action_name: "distributed-action"
    filter_name: "distributed-filter"

# 分析规则配置
analysis:
  ip_ban:
    max_attempts: 5
    time_window: 300
    ban_duration: 3600
    risk_threshold: 80.0
  
  patterns:
    sql_injection:
      - "union.*select"
      - "or.*1=1"
      - "drop.*table"
    
    xss:
      - "<script"
      - "javascript:"
      - "onerror="
    
    path_traversal:
      - "\.\./"
      - "etc/passwd"
      - "windows/system32"

# 白名单配置
whitelist:
  ips:
    - "127.0.0.1"
    - "::1"
    - "$LOCAL_IP"
  
  networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"

# 通知配置
notifications:
  email:
    enabled: false
    smtp_server: "smtp.example.com"
    smtp_port: 587
    username: "alert@example.com"
    password: "password"
    from_addr: "alert@example.com"
    to_addrs:
      - "admin@example.com"
  
  dingtalk:
    enabled: false
    webhook_url: ""
    secret: ""
  
  wechat:
    enabled: false
    corp_id: ""
    corp_secret: ""
    agent_id: ""

# Web界面配置
web:
  host: "0.0.0.0"
  port: 8080
  secret_key: "$SECRET_KEY"
  api_key: "$API_KEY"

# 性能设置
performance:
  max_workers: 4
  queue_size: 1000
  cache_ttl: 3600
  cleanup_interval: 86400
EOF
    
    # 设置权限
    chown fail2ban:fail2ban /etc/fail2ban-distributed/config.yaml
    chmod 600 /etc/fail2ban-distributed/config.yaml
    
    log_success "配置文件生成完成"
    log_info "API密钥: $API_KEY"
    log_info "Web密钥: $SECRET_KEY"
}

# 启动服务
start_services() {
    log_info "启动服务..."
    
    # 启动基础服务
    systemctl start redis
    systemctl start mongodb
    systemctl start nginx
    systemctl start fail2ban
    
    # 等待服务启动
    sleep 5
    
    # 根据模式启动对应服务
    read -p "请选择安装模式 [1.中央控制节点 2.日志收集代理 3.执行节点 4.全部]: " mode_choice
    
    case $mode_choice in
        1)
            systemctl enable fail2ban-central
            systemctl start fail2ban-central
            systemctl enable fail2ban-web
            systemctl start fail2ban-web
            log_success "中央控制节点启动完成"
            ;;
        2)
            systemctl enable fail2ban-agent
            systemctl start fail2ban-agent
            log_success "日志收集代理启动完成"
            ;;
        3)
            systemctl enable fail2ban-executor
            systemctl start fail2ban-executor
            log_success "执行节点启动完成"
            ;;
        4)
            systemctl enable fail2ban-central fail2ban-agent fail2ban-executor fail2ban-web
            systemctl start fail2ban-central fail2ban-agent fail2ban-executor fail2ban-web
            log_success "所有服务启动完成"
            ;;
        *)
            log_error "无效选择"
            exit 1
            ;;
    esac
}

# 显示安装结果
show_result() {
    log_success "=== 安装完成 ==="
    echo
    log_info "服务状态:"
    systemctl status fail2ban-central --no-pager -l || true
    systemctl status fail2ban-agent --no-pager -l || true
    systemctl status fail2ban-executor --no-pager -l || true
    systemctl status fail2ban-web --no-pager -l || true
    echo
    
    log_info "访问地址:"
    echo "  Web管理界面: http://$(hostname -I | awk '{print $1}'):8080"
    echo "  API接口: http://$(hostname -I | awk '{print $1}'):5000"
    echo
    
    log_info "配置文件位置:"
    echo "  主配置: /etc/fail2ban-distributed/config.yaml"
    echo "  日志目录: /var/log/fail2ban-distributed/"
    echo
    
    log_info "常用命令:"
    echo "  查看服务状态: systemctl status fail2ban-central"
    echo "  查看日志: journalctl -u fail2ban-central -f"
    echo "  重启服务: systemctl restart fail2ban-central"
    echo "  编辑配置: vi /etc/fail2ban-distributed/config.yaml"
    echo
    
    log_warning "请记住以下信息:"
    echo "  API密钥已保存在配置文件中"
    echo "  建议修改默认密码和密钥"
    echo "  确保防火墙已正确配置"
}

# 主函数
main() {
    echo "=================================="
    echo "  分布式Fail2ban系统安装脚本"
    echo "=================================="
    echo
    
    check_root
    detect_os
    
    log_info "开始安装..."
    
    install_dependencies
    install_python_deps
    create_user
    create_directories
    copy_files
    configure_services
    configure_firewall
    configure_nginx
    generate_config
    start_services
    
    show_result
    
    log_success "安装完成！"
}

# 运行主函数
main "$@"