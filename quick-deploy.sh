#!/bin/bash

# Fail2ban分布式系统快速部署脚本
# 支持一键部署到多台服务器

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

# 显示帮助信息
show_help() {
    cat << EOF
Fail2ban分布式系统快速部署脚本

用法: $0 [选项]

选项:
  -h, --help              显示此帮助信息
  -c, --config FILE       指定配置文件 (默认: deploy-config.yaml)
  -m, --mode MODE         部署模式: single|cluster (默认: single)
  -v, --verbose           详细输出
  --dry-run              仅显示将要执行的操作，不实际执行
  --skip-deps            跳过依赖安装
  --force                强制覆盖现有安装

部署模式:
  single                 单机部署 (所有组件在一台服务器)
  cluster                集群部署 (多台服务器分布式部署)

示例:
  $0                     # 单机部署
  $0 -m cluster          # 集群部署
  $0 -c my-config.yaml   # 使用自定义配置文件
  $0 --dry-run           # 预览部署操作

EOF
}

# 默认配置
CONFIG_FILE="deploy-config.yaml"
DEPLOY_MODE="single"
VERBOSE=false
DRY_RUN=false
SKIP_DEPS=false
FORCE=false

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -m|--mode)
            DEPLOY_MODE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
done

# 检查配置文件
if [[ ! -f "$CONFIG_FILE" ]]; then
    log_warning "配置文件 $CONFIG_FILE 不存在，创建默认配置文件"
    create_default_config
fi

# 创建默认配置文件
create_default_config() {
    cat > "$CONFIG_FILE" << 'EOF'
# Fail2ban分布式系统部署配置

# 全局配置
global:
  project_name: "fail2ban-distributed"
  version: "1.0.0"
  ssh_user: "root"
  ssh_key: "~/.ssh/id_rsa"
  
# 服务器配置
servers:
  # 中央控制节点
  central:
    host: "192.168.1.10"
    roles: ["central", "web"]
    
  # 日志收集代理节点
  agents:
    - host: "192.168.1.11"
      roles: ["agent"]
      log_paths:
        - "/var/log/nginx/access.log"
    - host: "192.168.1.12"
      roles: ["agent"]
      log_paths:
        - "/var/log/nginx/access.log"
        
  # 封禁执行节点
  executors:
    - host: "192.168.1.13"
      roles: ["executor"]
    - host: "192.168.1.14"
      roles: ["executor"]

# 数据库配置
database:
  redis:
    host: "192.168.1.10"
    port: 6379
  mongodb:
    host: "192.168.1.10"
    port: 27017
    
# 安全配置
security:
  api_key: "auto-generate"
  secret_key: "auto-generate"
  
# 通知配置
notifications:
  email:
    enabled: false
  dingtalk:
    enabled: false
  wechat:
    enabled: false
EOF
    log_success "已创建默认配置文件: $CONFIG_FILE"
}

# 读取配置文件
read_config() {
    if command -v yq >/dev/null 2>&1; then
        # 使用yq解析YAML
        CENTRAL_HOST=$(yq eval '.servers.central.host' "$CONFIG_FILE")
        AGENT_HOSTS=($(yq eval '.servers.agents[].host' "$CONFIG_FILE"))
        EXECUTOR_HOSTS=($(yq eval '.servers.executors[].host' "$CONFIG_FILE"))
    else
        log_warning "未安装yq，使用简单解析方式"
        # 简单解析（仅适用于标准格式）
        CENTRAL_HOST=$(grep -A1 "central:" "$CONFIG_FILE" | grep "host:" | awk '{print $2}' | tr -d '"')
        AGENT_HOSTS=($(grep -A10 "agents:" "$CONFIG_FILE" | grep "host:" | awk '{print $2}' | tr -d '"'))
        EXECUTOR_HOSTS=($(grep -A10 "executors:" "$CONFIG_FILE" | grep "host:" | awk '{print $2}' | tr -d '"'))
    fi
}

# 检查SSH连接
check_ssh_connection() {
    local host=$1
    local user=${SSH_USER:-root}
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] 检查SSH连接: $user@$host"
        return 0
    fi
    
    if ssh -o ConnectTimeout=10 -o BatchMode=yes "$user@$host" 'exit' 2>/dev/null; then
        log_success "SSH连接成功: $host"
        return 0
    else
        log_error "SSH连接失败: $host"
        return 1
    fi
}

# 在远程服务器上执行命令
execute_remote() {
    local host=$1
    local command=$2
    local user=${SSH_USER:-root}
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] 在 $host 执行: $command"
        return 0
    fi
    
    if [[ "$VERBOSE" == "true" ]]; then
        log_info "在 $host 执行: $command"
    fi
    
    ssh "$user@$host" "$command"
}

# 复制文件到远程服务器
copy_to_remote() {
    local host=$1
    local local_path=$2
    local remote_path=$3
    local user=${SSH_USER:-root}
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] 复制文件到 $host: $local_path -> $remote_path"
        return 0
    fi
    
    if [[ "$VERBOSE" == "true" ]]; then
        log_info "复制文件到 $host: $local_path -> $remote_path"
    fi
    
    scp -r "$local_path" "$user@$host:$remote_path"
}

# 生成配置文件
generate_config() {
    local host=$1
    local mode=$2
    local config_file="config-$host.yaml"
    
    log_info "为 $host 生成配置文件 ($mode 模式)"
    
    # 复制示例配置文件
    cp config.example.yaml "$config_file"
    
    # 根据模式修改配置
    case $mode in
        "central")
            sed -i "s/mode: \"central\"/mode: \"central\"/g" "$config_file"
            sed -i "s/host: \"central-server-ip\"/host: \"$CENTRAL_HOST\"/g" "$config_file"
            ;;
        "agent")
            sed -i "s/mode: \"central\"/mode: \"agent\"/g" "$config_file"
            sed -i "s/host: \"central-server-ip\"/host: \"$CENTRAL_HOST\"/g" "$config_file"
            ;;
        "executor")
            sed -i "s/mode: \"central\"/mode: \"executor\"/g" "$config_file"
            sed -i "s/host: \"central-server-ip\"/host: \"$CENTRAL_HOST\"/g" "$config_file"
            ;;
        "all")
            sed -i "s/mode: \"central\"/mode: \"all\"/g" "$config_file"
            ;;
    esac
    
    # 生成随机密钥
    if [[ "$DRY_RUN" != "true" ]]; then
        API_KEY=$(openssl rand -hex 32)
        SECRET_KEY=$(openssl rand -hex 32)
        sed -i "s/api_key: \"your-secure-api-key-here\"/api_key: \"$API_KEY\"/g" "$config_file"
        sed -i "s/secret_key: \"your-secret-key-here\"/secret_key: \"$SECRET_KEY\"/g" "$config_file"
    fi
    
    echo "$config_file"
}

# 部署到单台服务器
deploy_single() {
    local host=${1:-localhost}
    
    log_info "开始单机部署到: $host"
    
    # 检查SSH连接（如果不是本地部署）
    if [[ "$host" != "localhost" ]]; then
        check_ssh_connection "$host" || exit 1
    fi
    
    # 生成配置文件
    config_file=$(generate_config "$host" "all")
    
    if [[ "$host" == "localhost" ]]; then
        # 本地部署
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY-RUN] 本地执行安装脚本"
        else
            log_info "执行本地安装"
            sudo ./install.sh -m all -c "$config_file"
        fi
    else
        # 远程部署
        # 复制项目文件
        copy_to_remote "$host" "." "/tmp/fail2ban-distributed"
        
        # 复制配置文件
        copy_to_remote "$host" "$config_file" "/tmp/fail2ban-distributed/config.yaml"
        
        # 执行安装
        execute_remote "$host" "cd /tmp/fail2ban-distributed && sudo ./install.sh -m all -c config.yaml"
    fi
    
    log_success "单机部署完成"
}

# 部署到集群
deploy_cluster() {
    log_info "开始集群部署"
    
    # 读取配置
    read_config
    
    # 部署中央控制节点
    if [[ -n "$CENTRAL_HOST" ]]; then
        log_info "部署中央控制节点: $CENTRAL_HOST"
        check_ssh_connection "$CENTRAL_HOST" || exit 1
        
        config_file=$(generate_config "$CENTRAL_HOST" "central")
        copy_to_remote "$CENTRAL_HOST" "." "/tmp/fail2ban-distributed"
        copy_to_remote "$CENTRAL_HOST" "$config_file" "/tmp/fail2ban-distributed/config.yaml"
        execute_remote "$CENTRAL_HOST" "cd /tmp/fail2ban-distributed && sudo ./install.sh -m central -c config.yaml"
        
        log_success "中央控制节点部署完成"
    fi
    
    # 等待中央节点启动
    if [[ "$DRY_RUN" != "true" ]]; then
        log_info "等待中央节点启动..."
        sleep 10
    fi
    
    # 部署代理节点
    for agent_host in "${AGENT_HOSTS[@]}"; do
        if [[ -n "$agent_host" ]]; then
            log_info "部署代理节点: $agent_host"
            check_ssh_connection "$agent_host" || continue
            
            config_file=$(generate_config "$agent_host" "agent")
            copy_to_remote "$agent_host" "." "/tmp/fail2ban-distributed"
            copy_to_remote "$agent_host" "$config_file" "/tmp/fail2ban-distributed/config.yaml"
            execute_remote "$agent_host" "cd /tmp/fail2ban-distributed && sudo ./install.sh -m agent -c config.yaml"
            
            log_success "代理节点 $agent_host 部署完成"
        fi
    done
    
    # 部署执行节点
    for executor_host in "${EXECUTOR_HOSTS[@]}"; do
        if [[ -n "$executor_host" ]]; then
            log_info "部署执行节点: $executor_host"
            check_ssh_connection "$executor_host" || continue
            
            config_file=$(generate_config "$executor_host" "executor")
            copy_to_remote "$executor_host" "." "/tmp/fail2ban-distributed"
            copy_to_remote "$executor_host" "$config_file" "/tmp/fail2ban-distributed/config.yaml"
            execute_remote "$executor_host" "cd /tmp/fail2ban-distributed && sudo ./install.sh -m executor -c config.yaml"
            
            log_success "执行节点 $executor_host 部署完成"
        fi
    done
    
    log_success "集群部署完成"
}

# 检查部署状态
check_deployment() {
    log_info "检查部署状态"
    
    if [[ "$DEPLOY_MODE" == "single" ]]; then
        # 检查本地服务
        if systemctl is-active --quiet fail2ban-central; then
            log_success "中央服务运行正常"
        else
            log_error "中央服务未运行"
        fi
        
        if systemctl is-active --quiet fail2ban-web; then
            log_success "Web服务运行正常"
        else
            log_error "Web服务未运行"
        fi
    else
        # 检查集群服务
        read_config
        
        # 检查中央节点
        if [[ -n "$CENTRAL_HOST" ]]; then
            if execute_remote "$CENTRAL_HOST" "systemctl is-active --quiet fail2ban-central"; then
                log_success "中央节点 $CENTRAL_HOST 运行正常"
            else
                log_error "中央节点 $CENTRAL_HOST 未运行"
            fi
        fi
        
        # 检查代理节点
        for agent_host in "${AGENT_HOSTS[@]}"; do
            if [[ -n "$agent_host" ]]; then
                if execute_remote "$agent_host" "systemctl is-active --quiet fail2ban-agent"; then
                    log_success "代理节点 $agent_host 运行正常"
                else
                    log_error "代理节点 $agent_host 未运行"
                fi
            fi
        done
        
        # 检查执行节点
        for executor_host in "${EXECUTOR_HOSTS[@]}"; do
            if [[ -n "$executor_host" ]]; then
                if execute_remote "$executor_host" "systemctl is-active --quiet fail2ban-executor"; then
                    log_success "执行节点 $executor_host 运行正常"
                else
                    log_error "执行节点 $executor_host 未运行"
                fi
            fi
        done
    fi
}

# 显示部署信息
show_deployment_info() {
    log_info "部署信息"
    echo "==========================================="
    echo "部署模式: $DEPLOY_MODE"
    echo "配置文件: $CONFIG_FILE"
    
    if [[ "$DEPLOY_MODE" == "cluster" ]]; then
        read_config
        echo "中央节点: $CENTRAL_HOST"
        echo "代理节点: ${AGENT_HOSTS[*]}"
        echo "执行节点: ${EXECUTOR_HOSTS[*]}"
        echo ""
        echo "Web管理界面: http://$CENTRAL_HOST:8080"
        echo "API接口: http://$CENTRAL_HOST:5000"
    else
        echo "服务器: localhost"
        echo ""
        echo "Web管理界面: http://localhost:8080"
        echo "API接口: http://localhost:5000"
    fi
    echo "==========================================="
}

# 主函数
main() {
    log_info "Fail2ban分布式系统快速部署脚本"
    
    # 检查权限
    if [[ $EUID -eq 0 ]]; then
        log_warning "建议不要以root用户运行此脚本"
    fi
    
    # 检查必要工具
    if ! command -v ssh >/dev/null 2>&1; then
        log_error "未安装SSH客户端"
        exit 1
    fi
    
    if ! command -v scp >/dev/null 2>&1; then
        log_error "未安装SCP工具"
        exit 1
    fi
    
    # 显示部署信息
    show_deployment_info
    
    # 确认部署
    if [[ "$DRY_RUN" != "true" ]] && [[ "$FORCE" != "true" ]]; then
        echo ""
        read -p "确认开始部署? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "部署已取消"
            exit 0
        fi
    fi
    
    # 开始部署
    case $DEPLOY_MODE in
        "single")
            deploy_single
            ;;
        "cluster")
            deploy_cluster
            ;;
        *)
            log_error "不支持的部署模式: $DEPLOY_MODE"
            exit 1
            ;;
    esac
    
    # 检查部署状态
    if [[ "$DRY_RUN" != "true" ]]; then
        sleep 5
        check_deployment
    fi
    
    log_success "部署完成！"
    show_deployment_info
}

# 执行主函数
main "$@"