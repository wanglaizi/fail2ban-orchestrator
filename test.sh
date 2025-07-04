#!/bin/bash

# Fail2ban分布式系统测试脚本
# 用于测试系统各个组件的功能和性能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置
CONFIG_FILE="/etc/fail2ban-distributed/config.yaml"
TEST_LOG_FILE="/tmp/fail2ban-test.log"
TEST_IP="192.168.100.100"
CENTRAL_HOST="localhost"
CENTRAL_PORT="5000"
WEB_PORT="8080"

# 测试计数器
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$TEST_LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$TEST_LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$TEST_LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$TEST_LOG_FILE"
}

log_test() {
    echo -e "${CYAN}[TEST]${NC} $1" | tee -a "$TEST_LOG_FILE"
}

# 测试结果函数
test_pass() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "  ${GREEN}✓ PASS${NC} $1" | tee -a "$TEST_LOG_FILE"
}

test_fail() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "  ${RED}✗ FAIL${NC} $1" | tee -a "$TEST_LOG_FILE"
}

test_skip() {
    echo -e "  ${YELLOW}⊘ SKIP${NC} $1" | tee -a "$TEST_LOG_FILE"
}

# 显示帮助信息
show_help() {
    cat << EOF
Fail2ban分布式系统测试脚本

用法: $0 [选项] [测试类型]

测试类型:
  all                   运行所有测试 (默认)
  unit                  单元测试
  integration          集成测试
  performance          性能测试
  security             安全测试
  api                  API测试
  web                  Web界面测试
  stress               压力测试

选项:
  -h, --help           显示此帮助信息
  -c, --config FILE    指定配置文件
  -v, --verbose        详细输出
  --host HOST          中央服务器地址 (默认: localhost)
  --port PORT          中央服务器端口 (默认: 5000)
  --test-ip IP         测试用IP地址 (默认: 192.168.100.100)
  --no-cleanup         测试后不清理临时文件
  --parallel           并行运行测试

示例:
  $0                   # 运行所有测试
  $0 unit              # 只运行单元测试
  $0 api --host 192.168.1.10  # 测试远程API
  $0 performance -v    # 详细模式运行性能测试

EOF
}

# 解析命令行参数
parse_args() {
    TEST_TYPE="all"
    VERBOSE=false
    NO_CLEANUP=false
    PARALLEL=false
    
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
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --host)
                CENTRAL_HOST="$2"
                shift 2
                ;;
            --port)
                CENTRAL_PORT="$2"
                shift 2
                ;;
            --test-ip)
                TEST_IP="$2"
                shift 2
                ;;
            --no-cleanup)
                NO_CLEANUP=true
                shift
                ;;
            --parallel)
                PARALLEL=true
                shift
                ;;
            all|unit|integration|performance|security|api|web|stress)
                TEST_TYPE="$1"
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

# 初始化测试环境
init_test_env() {
    log_info "初始化测试环境"
    
    # 创建测试日志文件
    echo "Fail2ban分布式系统测试报告" > "$TEST_LOG_FILE"
    echo "测试时间: $(date)" >> "$TEST_LOG_FILE"
    echo "测试主机: $(hostname)" >> "$TEST_LOG_FILE"
    echo "========================================" >> "$TEST_LOG_FILE"
    
    # 检查必要工具
    local required_tools=("curl" "python3" "systemctl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "缺少必要工具: $tool"
            exit 1
        fi
    done
    
    log_success "测试环境初始化完成"
}

# 单元测试
run_unit_tests() {
    log_test "运行单元测试"
    
    # 测试配置文件解析
    if [[ -f "$CONFIG_FILE" ]]; then
        if python3 -c "import yaml; yaml.safe_load(open('$CONFIG_FILE'))" 2>/dev/null; then
            test_pass "配置文件语法正确"
        else
            test_fail "配置文件语法错误"
        fi
    else
        test_skip "配置文件不存在"
    fi
    
    # 测试Python模块导入
    local modules=("utils.logger" "utils.security" "utils.nginx_parser" "analysis.pattern_detector" "analysis.ip_analyzer")
    for module in "${modules[@]}"; do
        if python3 -c "import $module" 2>/dev/null; then
            test_pass "模块 $module 导入成功"
        else
            test_fail "模块 $module 导入失败"
        fi
    done
    
    # 测试日志解析器
    local test_log_line='127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"'
    if python3 -c "
from utils.nginx_parser import NginxLogParser
parser = NginxLogParser()
result = parser.parse_line('$test_log_line')
assert result is not None
assert result['remote_addr'] == '127.0.0.1'
print('日志解析测试通过')
" 2>/dev/null; then
        test_pass "日志解析器功能正常"
    else
        test_fail "日志解析器功能异常"
    fi
    
    # 测试攻击检测
    if python3 -c "
from analysis.pattern_detector import PatternDetector
detector = PatternDetector()
result = detector.detect_attack('/admin.php?id=1 union select')
assert len(result) > 0
print('攻击检测测试通过')
" 2>/dev/null; then
        test_pass "攻击检测功能正常"
    else
        test_fail "攻击检测功能异常"
    fi
}

# 集成测试
run_integration_tests() {
    log_test "运行集成测试"
    
    # 测试服务状态
    local services=("fail2ban-central" "fail2ban-agent" "fail2ban-executor" "fail2ban-web")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            test_pass "服务 $service 运行正常"
        elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
            test_fail "服务 $service 已安装但未运行"
        else
            test_skip "服务 $service 未安装"
        fi
    done
    
    # 测试数据库连接
    if command -v redis-cli >/dev/null 2>&1; then
        if redis-cli ping >/dev/null 2>&1; then
            test_pass "Redis连接正常"
        else
            test_fail "Redis连接失败"
        fi
    else
        test_skip "Redis客户端未安装"
    fi
    
    if command -v mongo >/dev/null 2>&1; then
        if mongo --eval "db.runCommand('ping')" >/dev/null 2>&1; then
            test_pass "MongoDB连接正常"
        else
            test_fail "MongoDB连接失败"
        fi
    else
        test_skip "MongoDB客户端未安装"
    fi
    
    # 测试端口监听
    local ports=("$CENTRAL_PORT" "5001" "$WEB_PORT")
    for port in "${ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            test_pass "端口 $port 正在监听"
        else
            test_fail "端口 $port 未监听"
        fi
    done
}

# API测试
run_api_tests() {
    log_test "运行API测试"
    
    local api_base="http://$CENTRAL_HOST:$CENTRAL_PORT"
    
    # 测试健康检查接口
    if curl -s "$api_base/api/health" >/dev/null 2>&1; then
        test_pass "健康检查API响应正常"
    else
        test_fail "健康检查API无响应"
    fi
    
    # 测试统计接口
    if curl -s "$api_base/api/stats" >/dev/null 2>&1; then
        test_pass "统计API响应正常"
    else
        test_fail "统计API无响应"
    fi
    
    # 测试封禁列表接口
    if curl -s "$api_base/api/banned-ips" >/dev/null 2>&1; then
        test_pass "封禁列表API响应正常"
    else
        test_fail "封禁列表API无响应"
    fi
    
    # 测试节点状态接口
    if curl -s "$api_base/api/nodes" >/dev/null 2>&1; then
        test_pass "节点状态API响应正常"
    else
        test_fail "节点状态API无响应"
    fi
}

# Web界面测试
run_web_tests() {
    log_test "运行Web界面测试"
    
    local web_base="http://$CENTRAL_HOST:$WEB_PORT"
    
    # 测试主页
    if curl -s "$web_base/" | grep -q "Fail2ban" 2>/dev/null; then
        test_pass "Web主页加载正常"
    else
        test_fail "Web主页加载失败"
    fi
    
    # 测试静态资源
    if curl -s "$web_base/static/css/style.css" >/dev/null 2>&1; then
        test_pass "CSS文件加载正常"
    else
        test_fail "CSS文件加载失败"
    fi
    
    if curl -s "$web_base/static/js/app.js" >/dev/null 2>&1; then
        test_pass "JavaScript文件加载正常"
    else
        test_fail "JavaScript文件加载失败"
    fi
}

# 性能测试
run_performance_tests() {
    log_test "运行性能测试"
    
    local api_base="http://$CENTRAL_HOST:$CENTRAL_PORT"
    
    # 测试API响应时间
    local response_time=$(curl -o /dev/null -s -w "%{time_total}" "$api_base/api/health" 2>/dev/null || echo "999")
    if (( $(echo "$response_time < 1.0" | bc -l) )); then
        test_pass "API响应时间正常 (${response_time}s)"
    else
        test_fail "API响应时间过长 (${response_time}s)"
    fi
    
    # 测试并发请求
    log_info "测试并发请求处理能力"
    local concurrent_requests=10
    local start_time=$(date +%s.%N)
    
    for i in $(seq 1 $concurrent_requests); do
        curl -s "$api_base/api/health" >/dev/null 2>&1 &
    done
    wait
    
    local end_time=$(date +%s.%N)
    local total_time=$(echo "$end_time - $start_time" | bc)
    
    if (( $(echo "$total_time < 5.0" | bc -l) )); then
        test_pass "并发请求处理正常 (${concurrent_requests}个请求用时${total_time}s)"
    else
        test_fail "并发请求处理缓慢 (${concurrent_requests}个请求用时${total_time}s)"
    fi
    
    # 测试内存使用
    local memory_usage=$(ps aux | grep -E "fail2ban|python3.*main.py" | grep -v grep | awk '{sum+=$6} END {print sum/1024}')
    if [[ -n "$memory_usage" ]] && (( $(echo "$memory_usage < 500" | bc -l) )); then
        test_pass "内存使用正常 (${memory_usage}MB)"
    else
        test_fail "内存使用过高 (${memory_usage}MB)"
    fi
}

# 安全测试
run_security_tests() {
    log_test "运行安全测试"
    
    local api_base="http://$CENTRAL_HOST:$CENTRAL_PORT"
    
    # 测试未授权访问
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$api_base/api/ban" -X POST 2>/dev/null || echo "000")
    if [[ "$status_code" == "401" ]] || [[ "$status_code" == "403" ]]; then
        test_pass "API访问控制正常"
    else
        test_fail "API访问控制异常 (状态码: $status_code)"
    fi
    
    # 测试SQL注入防护
    local malicious_payload="'; DROP TABLE users; --"
    local response=$(curl -s "$api_base/api/stats?filter=$malicious_payload" 2>/dev/null || echo "error")
    if [[ "$response" != "error" ]] && ! echo "$response" | grep -q "error\|exception" 2>/dev/null; then
        test_pass "SQL注入防护正常"
    else
        test_fail "SQL注入防护异常"
    fi
    
    # 测试XSS防护
    local xss_payload="<script>alert('xss')</script>"
    local response=$(curl -s "$api_base/api/stats?q=$xss_payload" 2>/dev/null || echo "error")
    if [[ "$response" != "error" ]] && ! echo "$response" | grep -q "<script>" 2>/dev/null; then
        test_pass "XSS防护正常"
    else
        test_fail "XSS防护异常"
    fi
}

# 压力测试
run_stress_tests() {
    log_test "运行压力测试"
    
    local api_base="http://$CENTRAL_HOST:$CENTRAL_PORT"
    
    log_info "开始压力测试 (持续30秒)"
    
    # 创建压力测试脚本
    cat > /tmp/stress_test.sh << 'EOF'
#!/bin/bash
api_base="$1"
end_time=$(($(date +%s) + 30))
request_count=0

while [[ $(date +%s) -lt $end_time ]]; do
    curl -s "$api_base/api/health" >/dev/null 2>&1
    request_count=$((request_count + 1))
done

echo $request_count
EOF
    
    chmod +x /tmp/stress_test.sh
    
    # 启动多个并发进程
    local processes=5
    local pids=()
    
    for i in $(seq 1 $processes); do
        /tmp/stress_test.sh "$api_base" > "/tmp/stress_result_$i" &
        pids+=("$!")
    done
    
    # 等待所有进程完成
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    # 统计结果
    local total_requests=0
    for i in $(seq 1 $processes); do
        local count=$(cat "/tmp/stress_result_$i" 2>/dev/null || echo "0")
        total_requests=$((total_requests + count))
    done
    
    local rps=$((total_requests / 30))
    
    if [[ $rps -gt 50 ]]; then
        test_pass "压力测试通过 (${total_requests}个请求, ${rps} RPS)"
    else
        test_fail "压力测试失败 (${total_requests}个请求, ${rps} RPS)"
    fi
    
    # 清理临时文件
    rm -f /tmp/stress_test.sh /tmp/stress_result_*
}

# 功能测试
run_functional_tests() {
    log_test "运行功能测试"
    
    # 测试IP封禁功能
    log_info "测试IP封禁功能"
    
    # 模拟攻击日志
    local attack_log="$TEST_IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /admin.php?id=1' union select HTTP/1.1\" 404 0 \"-\" \"sqlmap/1.0\""
    
    # 创建临时日志文件
    echo "$attack_log" > /tmp/test_access.log
    
    # 测试日志解析和攻击检测
    if python3 -c "
import sys
sys.path.append('/opt/fail2ban')
from utils.nginx_parser import NginxLogParser
from analysis.pattern_detector import PatternDetector

parser = NginxLogParser()
detector = PatternDetector()

with open('/tmp/test_access.log', 'r') as f:
    line = f.readline().strip()
    
result = parser.parse_line(line)
if result:
    attacks = detector.detect_attack(result.get('request', ''))
    if attacks:
        print('攻击检测成功:', attacks)
        exit(0)
    else:
        print('未检测到攻击')
        exit(1)
else:
    print('日志解析失败')
    exit(1)
" 2>/dev/null; then
        test_pass "攻击检测和日志解析功能正常"
    else
        test_fail "攻击检测和日志解析功能异常"
    fi
    
    # 清理临时文件
    rm -f /tmp/test_access.log
}

# 清理测试环境
cleanup_test_env() {
    if [[ "$NO_CLEANUP" != "true" ]]; then
        log_info "清理测试环境"
        
        # 清理临时文件
        rm -f /tmp/fail2ban-test-* /tmp/stress_* /tmp/test_*
        
        log_success "测试环境清理完成"
    fi
}

# 生成测试报告
generate_report() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}           测试报告摘要${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "总测试数: ${BLUE}$TOTAL_TESTS${NC}"
    echo -e "通过测试: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "失败测试: ${RED}$FAILED_TESTS${NC}"
    
    local success_rate=0
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    fi
    
    echo -e "成功率: ${success_rate}%"
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}所有测试通过！${NC}"
    else
        echo -e "${RED}有 $FAILED_TESTS 个测试失败${NC}"
    fi
    
    echo -e "${CYAN}========================================${NC}"
    echo -e "详细测试日志: $TEST_LOG_FILE"
    echo ""
}

# 主函数
main() {
    parse_args "$@"
    
    log_info "开始Fail2ban分布式系统测试"
    log_info "测试类型: $TEST_TYPE"
    log_info "中央服务器: $CENTRAL_HOST:$CENTRAL_PORT"
    
    init_test_env
    
    case $TEST_TYPE in
        "all")
            run_unit_tests
            run_integration_tests
            run_api_tests
            run_web_tests
            run_functional_tests
            run_performance_tests
            run_security_tests
            ;;
        "unit")
            run_unit_tests
            ;;
        "integration")
            run_integration_tests
            ;;
        "api")
            run_api_tests
            ;;
        "web")
            run_web_tests
            ;;
        "performance")
            run_performance_tests
            ;;
        "security")
            run_security_tests
            ;;
        "stress")
            run_stress_tests
            ;;
        *)
            log_error "不支持的测试类型: $TEST_TYPE"
            exit 1
            ;;
    esac
    
    cleanup_test_env
    generate_report
    
    # 根据测试结果设置退出码
    if [[ $FAILED_TESTS -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# 信号处理
trap 'echo -e "\n${YELLOW}测试被中断${NC}"; cleanup_test_env; exit 130' INT TERM

# 执行主函数
main "$@"