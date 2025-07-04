#!/bin/bash

# Fail2ban分布式系统监控脚本
# 用于监控系统运行状态、性能指标和健康状况

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置文件路径
CONFIG_FILE="/etc/fail2ban-distributed/config.yaml"
LOG_DIR="/var/log/fail2ban-distributed"
PID_DIR="/var/run"

# 默认参数
MONITOR_MODE="status"
REFRESH_INTERVAL=5
OUTPUT_FORMAT="table"
SHOW_DETAILS=false
CONTINUOUS=false
LOG_LINES=50

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

log_debug() {
    echo -e "${PURPLE}[DEBUG]${NC} $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Fail2ban分布式系统监控脚本

用法: $0 [选项] [模式]

模式:
  status                 显示服务状态 (默认)
  performance           显示性能指标
  logs                  显示日志信息
  stats                 显示统计信息
  health                健康检查
  dashboard             实时监控面板
  alerts                显示告警信息

选项:
  -h, --help            显示此帮助信息
  -c, --config FILE     指定配置文件 (默认: $CONFIG_FILE)
  -i, --interval SEC    刷新间隔秒数 (默认: $REFRESH_INTERVAL)
  -f, --format FORMAT   输出格式: table|json|csv (默认: $OUTPUT_FORMAT)
  -d, --details         显示详细信息
  -w, --watch           持续监控模式
  -n, --lines NUM       日志行数 (默认: $LOG_LINES)
  --no-color            禁用颜色输出

示例:
  $0                    # 显示服务状态
  $0 performance        # 显示性能指标
  $0 logs -n 100        # 显示最近100行日志
  $0 dashboard -w       # 实时监控面板
  $0 stats -f json      # JSON格式输出统计信息

EOF
}

# 解析命令行参数
parse_args() {
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
            -i|--interval)
                REFRESH_INTERVAL="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -d|--details)
                SHOW_DETAILS=true
                shift
                ;;
            -w|--watch)
                CONTINUOUS=true
                shift
                ;;
            -n|--lines)
                LOG_LINES="$2"
                shift 2
                ;;
            --no-color)
                RED=''
                GREEN=''
                YELLOW=''
                BLUE=''
                PURPLE=''
                CYAN=''
                NC=''
                shift
                ;;
            status|performance|logs|stats|health|dashboard|alerts)
                MONITOR_MODE="$1"
                shift
                ;;
            *)
                log_error "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 获取系统信息
get_system_info() {
    echo "系统信息:"
    echo "  操作系统: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')"
    echo "  内核版本: $(uname -r)"
    echo "  主机名: $(hostname)"
    echo "  运行时间: $(uptime -p)"
    echo "  当前时间: $(date)"
    echo ""
}

# 检查服务状态
check_service_status() {
    local service=$1
    local display_name=$2
    
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $display_name: ${GREEN}运行中${NC}"
        if [[ "$SHOW_DETAILS" == "true" ]]; then
            local pid=$(systemctl show --property MainPID --value "$service")
            local memory=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{print $1/1024 " MB"}' || echo "N/A")
            local cpu=$(ps -o %cpu= -p "$pid" 2>/dev/null | awk '{print $1 "%"}' || echo "N/A")
            echo "    PID: $pid, 内存: $memory, CPU: $cpu"
        fi
    elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
        echo -e "  ${RED}✗${NC} $display_name: ${RED}已停止${NC}"
    else
        echo -e "  ${YELLOW}?${NC} $display_name: ${YELLOW}未安装${NC}"
    fi
}

# 显示服务状态
show_status() {
    echo -e "${CYAN}=== 服务状态 ===${NC}"
    
    check_service_status "fail2ban-central" "中央控制服务"
    check_service_status "fail2ban-agent" "日志收集代理"
    check_service_status "fail2ban-executor" "封禁执行服务"
    check_service_status "fail2ban-web" "Web管理界面"
    check_service_status "fail2ban" "Fail2ban服务"
    check_service_status "redis" "Redis数据库"
    check_service_status "mongodb" "MongoDB数据库"
    check_service_status "nginx" "Nginx服务"
    
    echo ""
    
    # 检查端口状态
    echo -e "${CYAN}=== 端口状态 ===${NC}"
    check_port "5000" "API服务"
    check_port "5001" "WebSocket服务"
    check_port "8080" "Web界面"
    check_port "6379" "Redis"
    check_port "27017" "MongoDB"
    
    echo ""
}

# 检查端口状态
check_port() {
    local port=$1
    local service=$2
    
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        echo -e "  ${GREEN}✓${NC} $service (端口 $port): ${GREEN}监听中${NC}"
    else
        echo -e "  ${RED}✗${NC} $service (端口 $port): ${RED}未监听${NC}"
    fi
}

# 显示性能指标
show_performance() {
    echo -e "${CYAN}=== 系统性能 ===${NC}"
    
    # CPU使用率
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    echo -e "  CPU使用率: ${cpu_usage}%"
    
    # 内存使用情况
    local mem_info=$(free -h | grep "Mem:")
    local mem_total=$(echo $mem_info | awk '{print $2}')
    local mem_used=$(echo $mem_info | awk '{print $3}')
    local mem_percent=$(free | grep "Mem:" | awk '{printf "%.1f", $3/$2 * 100.0}')
    echo -e "  内存使用: $mem_used / $mem_total (${mem_percent}%)"
    
    # 磁盘使用情况
    echo "  磁盘使用:"
    df -h | grep -E "^/dev/" | while read line; do
        local usage=$(echo $line | awk '{print $5}' | cut -d'%' -f1)
        local mount=$(echo $line | awk '{print $6}')
        local used=$(echo $line | awk '{print $3}')
        local total=$(echo $line | awk '{print $2}')
        
        if [[ $usage -gt 90 ]]; then
            echo -e "    ${RED}$mount: $used / $total (${usage}%)${NC}"
        elif [[ $usage -gt 80 ]]; then
            echo -e "    ${YELLOW}$mount: $used / $total (${usage}%)${NC}"
        else
            echo -e "    ${GREEN}$mount: $used / $total (${usage}%)${NC}"
        fi
    done
    
    # 网络连接
    local connections=$(netstat -an 2>/dev/null | grep -E ":(5000|5001|8080)" | wc -l)
    echo -e "  活跃连接数: $connections"
    
    # 进程信息
    echo ""
    echo -e "${CYAN}=== 进程信息 ===${NC}"
    ps aux | grep -E "fail2ban|redis|mongo" | grep -v grep | while read line; do
        local user=$(echo $line | awk '{print $1}')
        local pid=$(echo $line | awk '{print $2}')
        local cpu=$(echo $line | awk '{print $3}')
        local mem=$(echo $line | awk '{print $4}')
        local cmd=$(echo $line | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
        echo "  PID: $pid, 用户: $user, CPU: ${cpu}%, 内存: ${mem}%, 命令: $cmd"
    done
    
    echo ""
}

# 显示日志信息
show_logs() {
    echo -e "${CYAN}=== 系统日志 ===${NC}"
    
    if [[ -f "$LOG_DIR/system.log" ]]; then
        echo "最近 $LOG_LINES 行系统日志:"
        tail -n "$LOG_LINES" "$LOG_DIR/system.log" | while read line; do
            if echo "$line" | grep -q "ERROR"; then
                echo -e "${RED}$line${NC}"
            elif echo "$line" | grep -q "WARNING"; then
                echo -e "${YELLOW}$line${NC}"
            elif echo "$line" | grep -q "banned"; then
                echo -e "${GREEN}$line${NC}"
            else
                echo "$line"
            fi
        done
    else
        log_warning "系统日志文件不存在: $LOG_DIR/system.log"
    fi
    
    echo ""
    
    # 显示错误日志
    if [[ -f "$LOG_DIR/error.log" ]]; then
        local error_count=$(wc -l < "$LOG_DIR/error.log")
        if [[ $error_count -gt 0 ]]; then
            echo -e "${RED}最近错误日志 (共 $error_count 条):${NC}"
            tail -n 10 "$LOG_DIR/error.log"
        fi
    fi
    
    echo ""
}

# 显示统计信息
show_stats() {
    echo -e "${CYAN}=== 统计信息 ===${NC}"
    
    # 封禁统计
    if [[ -f "$LOG_DIR/system.log" ]]; then
        local total_bans=$(grep -c "IP banned" "$LOG_DIR/system.log" 2>/dev/null || echo "0")
        local today_bans=$(grep "IP banned" "$LOG_DIR/system.log" 2>/dev/null | grep "$(date '+%Y-%m-%d')" | wc -l)
        echo "  总封禁次数: $total_bans"
        echo "  今日封禁: $today_bans"
        
        # 最常被封禁的IP
        echo ""
        echo "  最常被封禁的IP (Top 10):"
        grep "IP banned" "$LOG_DIR/system.log" 2>/dev/null | \
            awk '{print $NF}' | sort | uniq -c | sort -nr | head -10 | \
            while read count ip; do
                echo "    $ip: $count 次"
            done
        
        # 攻击类型统计
        echo ""
        echo "  攻击类型统计:"
        grep "Attack detected" "$LOG_DIR/system.log" 2>/dev/null | \
            awk '{print $(NF-1)}' | sort | uniq -c | sort -nr | \
            while read count type; do
                echo "    $type: $count 次"
            done
    fi
    
    # 数据库统计
    echo ""
    echo -e "${CYAN}=== 数据库统计 ===${NC}"
    
    # Redis统计
    if command -v redis-cli >/dev/null 2>&1; then
        local redis_info=$(redis-cli info memory 2>/dev/null || echo "连接失败")
        if [[ "$redis_info" != "连接失败" ]]; then
            local used_memory=$(echo "$redis_info" | grep "used_memory_human:" | cut -d':' -f2 | tr -d '\r')
            local keys=$(redis-cli dbsize 2>/dev/null || echo "0")
            echo "  Redis内存使用: $used_memory"
            echo "  Redis键数量: $keys"
        else
            echo "  Redis: 连接失败"
        fi
    fi
    
    # MongoDB统计
    if command -v mongo >/dev/null 2>&1; then
        local mongo_stats=$(mongo --quiet --eval "db.stats()" 2>/dev/null || echo "连接失败")
        if [[ "$mongo_stats" != "连接失败" ]]; then
            echo "  MongoDB: 连接正常"
        else
            echo "  MongoDB: 连接失败"
        fi
    fi
    
    echo ""
}

# 健康检查
health_check() {
    echo -e "${CYAN}=== 健康检查 ===${NC}"
    
    local health_score=100
    local issues=()
    
    # 检查服务状态
    local services=("fail2ban-central" "fail2ban-agent" "fail2ban-executor" "fail2ban-web")
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service" 2>/dev/null; then
            if systemctl is-enabled --quiet "$service" 2>/dev/null; then
                health_score=$((health_score - 20))
                issues+=("服务 $service 未运行")
            fi
        fi
    done
    
    # 检查磁盘空间
    df -h | grep -E "^/dev/" | while read line; do
        local usage=$(echo $line | awk '{print $5}' | cut -d'%' -f1)
        local mount=$(echo $line | awk '{print $6}')
        
        if [[ $usage -gt 95 ]]; then
            health_score=$((health_score - 30))
            issues+=("磁盘空间不足: $mount (${usage}%)")
        elif [[ $usage -gt 90 ]]; then
            health_score=$((health_score - 10))
            issues+=("磁盘空间告警: $mount (${usage}%)")
        fi
    done
    
    # 检查内存使用
    local mem_percent=$(free | grep "Mem:" | awk '{printf "%.0f", $3/$2 * 100.0}')
    if [[ $mem_percent -gt 90 ]]; then
        health_score=$((health_score - 20))
        issues+=("内存使用过高: ${mem_percent}%")
    elif [[ $mem_percent -gt 80 ]]; then
        health_score=$((health_score - 10))
        issues+=("内存使用告警: ${mem_percent}%")
    fi
    
    # 检查日志错误
    if [[ -f "$LOG_DIR/error.log" ]]; then
        local recent_errors=$(find "$LOG_DIR/error.log" -mmin -60 -exec wc -l {} \; 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
        if [[ $recent_errors -gt 10 ]]; then
            health_score=$((health_score - 15))
            issues+=("最近1小时内有 $recent_errors 个错误")
        fi
    fi
    
    # 显示健康评分
    if [[ $health_score -ge 90 ]]; then
        echo -e "  健康评分: ${GREEN}$health_score/100 (优秀)${NC}"
    elif [[ $health_score -ge 70 ]]; then
        echo -e "  健康评分: ${YELLOW}$health_score/100 (良好)${NC}"
    elif [[ $health_score -ge 50 ]]; then
        echo -e "  健康评分: ${YELLOW}$health_score/100 (一般)${NC}"
    else
        echo -e "  健康评分: ${RED}$health_score/100 (差)${NC}"
    fi
    
    # 显示问题列表
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo ""
        echo -e "${RED}发现的问题:${NC}"
        for issue in "${issues[@]}"; do
            echo -e "  ${RED}✗${NC} $issue"
        done
    else
        echo -e "  ${GREEN}✓ 未发现问题${NC}"
    fi
    
    echo ""
}

# 显示告警信息
show_alerts() {
    echo -e "${CYAN}=== 告警信息 ===${NC}"
    
    # 检查最近的错误
    if [[ -f "$LOG_DIR/error.log" ]]; then
        local recent_errors=$(find "$LOG_DIR/error.log" -mmin -60 2>/dev/null)
        if [[ -n "$recent_errors" ]]; then
            echo -e "${RED}最近1小时内的错误:${NC}"
            tail -n 20 "$LOG_DIR/error.log" | while read line; do
                echo -e "  ${RED}$line${NC}"
            done
        else
            echo -e "${GREEN}最近1小时内无错误${NC}"
        fi
    fi
    
    # 检查异常封禁
    if [[ -f "$LOG_DIR/system.log" ]]; then
        local recent_bans=$(grep "IP banned" "$LOG_DIR/system.log" | grep "$(date '+%Y-%m-%d')" | wc -l)
        if [[ $recent_bans -gt 100 ]]; then
            echo -e "${RED}告警: 今日封禁次数异常 ($recent_bans 次)${NC}"
        fi
    fi
    
    echo ""
}

# 实时监控面板
show_dashboard() {
    while true; do
        clear
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    Fail2ban 分布式系统监控面板                    ║${NC}"
        echo -e "${CYAN}║                    刷新间隔: ${REFRESH_INTERVAL}秒 | 按 Ctrl+C 退出                  ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        get_system_info
        show_status
        show_performance
        
        if [[ "$CONTINUOUS" != "true" ]]; then
            break
        fi
        
        sleep "$REFRESH_INTERVAL"
    done
}

# JSON格式输出
output_json() {
    echo "{"
    echo '  "timestamp": "'$(date -Iseconds)'",'
    echo '  "system": {'
    echo '    "hostname": "'$(hostname)'",'
    echo '    "uptime": "'$(uptime -p)'",'
    echo '    "os": "'$(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')'",'
    echo '    "kernel": "'$(uname -r)'"'
    echo '  },'
    echo '  "services": {'
    
    local services=("fail2ban-central" "fail2ban-agent" "fail2ban-executor" "fail2ban-web")
    for i in "${!services[@]}"; do
        local service="${services[$i]}"
        local status="stopped"
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            status="running"
        fi
        echo '    "'$service'": "'$status'"'
        if [[ $i -lt $((${#services[@]} - 1)) ]]; then
            echo ","
        fi
    done
    
    echo '  }'
    echo "}"
}

# 主函数
main() {
    parse_args "$@"
    
    # 检查配置文件
    if [[ ! -f "$CONFIG_FILE" ]] && [[ "$MONITOR_MODE" != "status" ]]; then
        log_warning "配置文件不存在: $CONFIG_FILE"
    fi
    
    # 根据输出格式处理
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_json
        exit 0
    fi
    
    # 显示系统信息
    if [[ "$MONITOR_MODE" != "dashboard" ]]; then
        get_system_info
    fi
    
    # 根据模式执行相应功能
    case $MONITOR_MODE in
        "status")
            show_status
            ;;
        "performance")
            show_performance
            ;;
        "logs")
            show_logs
            ;;
        "stats")
            show_stats
            ;;
        "health")
            health_check
            ;;
        "dashboard")
            show_dashboard
            ;;
        "alerts")
            show_alerts
            ;;
        *)
            log_error "不支持的监控模式: $MONITOR_MODE"
            exit 1
            ;;
    esac
}

# 信号处理
trap 'echo -e "\n${YELLOW}监控已停止${NC}"; exit 0' INT TERM

# 执行主函数
main "$@"