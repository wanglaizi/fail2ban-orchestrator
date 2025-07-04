# Fail2ban分布式系统用户手册

## 目录

1. [系统概述](#系统概述)
2. [快速开始](#快速开始)
3. [系统架构](#系统架构)
4. [安装部署](#安装部署)
5. [配置说明](#配置说明)
6. [使用指南](#使用指南)
7. [Web管理界面](#web管理界面)
8. [命令行工具](#命令行工具)
9. [监控运维](#监控运维)
10. [故障排除](#故障排除)
11. [最佳实践](#最佳实践)
12. [FAQ](#faq)

## 系统概述

Fail2ban分布式系统是一个基于Python开发的分布式入侵防护系统，专门设计用于保护多台服务器免受网络攻击。系统通过实时分析Nginx日志，智能检测各种攻击模式，并自动执行IP封禁操作。

### 核心特性

- **分布式架构**: 支持多节点部署，可横向扩展
- **实时监控**: 实时分析日志文件，快速响应攻击
- **智能检测**: 支持多种攻击模式检测，包括SQL注入、XSS、路径遍历等
- **动态封禁**: 基于风险评分的智能封禁策略
- **Web界面**: 直观的Web管理界面，支持实时监控和操作
- **多渠道通知**: 支持邮件、钉钉、微信、Slack等通知方式
- **高可用性**: 支持Redis和MongoDB集群，确保系统稳定性

### 适用场景

- 多台Web服务器的集中防护
- 三网环境（电信、联通、移动）的分布式部署
- 海外服务器的统一管理
- 大流量网站的安全防护
- 企业级安全运营中心(SOC)

## 快速开始

### 系统要求

- **操作系统**: CentOS 7/8, Ubuntu 18.04/20.04/22.04
- **Python**: 3.7+
- **内存**: 最低2GB，推荐4GB+
- **磁盘**: 最低10GB可用空间
- **网络**: 节点间需要网络互通

### 一键安装

```bash
# 下载安装脚本
wget https://github.com/your-repo/fail2ban-distributed/releases/latest/download/install.sh

# 赋予执行权限
chmod +x install.sh

# 运行安装脚本
sudo ./install.sh
```

### 验证安装

```bash
# 检查服务状态
sudo systemctl status fail2ban-central
sudo systemctl status fail2ban-web

# 访问Web界面
http://your-server-ip:8080
```

## 系统架构

### 组件说明

#### 1. 中央控制节点 (Central Node)

负责整个系统的协调和管理：

- 接收来自代理节点的日志数据
- 执行攻击检测和风险评估
- 管理封禁策略和白名单
- 向执行节点下发封禁指令
- 提供API接口和WebSocket服务

#### 2. 日志收集代理 (Agent Node)

部署在需要监控的服务器上：

- 实时监控Nginx日志文件
- 解析日志并提取关键信息
- 批量发送数据到中央控制节点
- 支持多种日志格式

#### 3. 封禁执行节点 (Executor Node)

负责执行具体的封禁操作：

- 接收中央节点的封禁指令
- 调用Fail2ban执行IP封禁
- 管理本地iptables规则
- 报告执行状态

#### 4. Web管理界面 (Web Dashboard)

提供可视化管理界面：

- 实时监控系统状态
- 查看攻击统计和趋势
- 手动管理IP封禁
- 配置系统参数

### 数据流程

```
[Nginx日志] → [代理节点] → [中央控制节点] → [执行节点] → [Fail2ban/iptables]
                                ↓
                          [Web界面/API]
                                ↓
                          [通知系统]
```

## 安装部署

### 单机部署

适用于小规模环境或测试环境：

```bash
# 运行安装脚本并选择单机模式
sudo ./install.sh
# 选择: [4] 完整部署 (所有组件)

# 启动所有服务
sudo systemctl start fail2ban-central
sudo systemctl start fail2ban-agent
sudo systemctl start fail2ban-executor
sudo systemctl start fail2ban-web
```

### 分布式部署

#### 步骤1: 部署中央控制节点

在主控服务器上：

```bash
# 安装中央控制节点
sudo ./install.sh
# 选择: [1] 中央控制节点

# 编辑配置文件
sudo vim /etc/fail2ban-distributed/config.yaml

# 启动服务
sudo systemctl start fail2ban-central
sudo systemctl start fail2ban-web
```

#### 步骤2: 部署代理节点

在需要监控的Web服务器上：

```bash
# 安装代理节点
sudo ./install.sh
# 选择: [2] 日志收集代理

# 配置中央服务器地址
sudo vim /etc/fail2ban-distributed/config.yaml
# 修改 central_server.host 为中央服务器IP

# 启动服务
sudo systemctl start fail2ban-agent
```

#### 步骤3: 部署执行节点

在需要执行封禁的服务器上：

```bash
# 安装执行节点
sudo ./install.sh
# 选择: [3] 封禁执行节点

# 配置中央服务器地址
sudo vim /etc/fail2ban-distributed/config.yaml

# 启动服务
sudo systemctl start fail2ban-executor
```

### 快速部署脚本

使用提供的快速部署脚本：

```bash
# 集群部署
./quick-deploy.sh -m cluster -c deploy-config.yaml

# 单机部署
./quick-deploy.sh -m single
```

## 配置说明

### 主配置文件

配置文件位置：`/etc/fail2ban-distributed/config.yaml`

#### 基础配置

```yaml
system:
  mode: "central"  # 运行模式: central, agent, executor, all
  log_level: "INFO"  # 日志级别
  api_key: "your-api-key"  # API密钥
  secret_key: "your-secret-key"  # 加密密钥
```

#### 中央控制节点配置

```yaml
central:
  api:
    host: "0.0.0.0"
    port: 5000
  
  database:
    redis:
      host: "localhost"
      port: 6379
    mongodb:
      host: "localhost"
      port: 27017
      database: "fail2ban_distributed"
  
  ban_policy:
    default_ban_time: 3600  # 默认封禁时间(秒)
    risk_threshold: 80      # 风险评分阈值
    attack_threshold: 5     # 攻击次数阈值
```

#### 代理节点配置

```yaml
agent:
  central_server:
    host: "central-server-ip"
    port: 5000
  
  log_monitor:
    log_paths:
      - "/var/log/nginx/access.log"
    log_format: "nginx_combined"
    check_interval: 1
```

#### 执行节点配置

```yaml
executor:
  central_server:
    host: "central-server-ip"
    port: 5000
  
  fail2ban:
    client_path: "/usr/bin/fail2ban-client"
    jail_name: "distributed-ban"
```

### 通知配置

#### 邮件通知

```yaml
notifications:
  email:
    enabled: true
    smtp_server: "smtp.example.com"
    smtp_port: 587
    username: "your-email@example.com"
    password: "your-password"
    from_email: "fail2ban@example.com"
    to_emails:
      - "admin@example.com"
    use_tls: true
```

#### 钉钉通知

```yaml
notifications:
  dingtalk:
    enabled: true
    webhook_url: "https://oapi.dingtalk.com/robot/send?access_token=your-token"
    secret: "your-secret"
```

#### 微信通知

```yaml
notifications:
  wechat:
    enabled: true
    webhook_url: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=your-key"
```

### 检测规则配置

```yaml
detection:
  patterns:
    enabled_types:
      - "sql_injection"
      - "xss"
      - "path_traversal"
      - "command_injection"
      - "file_inclusion"
      - "scanner"
      - "brute_force"
  
  frequency:
    high_frequency:
      window: 60      # 时间窗口(秒)
      threshold: 100  # 请求阈值
    
    error_404:
      window: 300
      threshold: 20
      rate_threshold: 50  # 错误率阈值(%)
```

## 使用指南

### 启动系统

#### 启动所有服务

```bash
# 启动中央控制服务
sudo systemctl start fail2ban-central

# 启动Web界面
sudo systemctl start fail2ban-web

# 启动代理服务(在代理节点上)
sudo systemctl start fail2ban-agent

# 启动执行服务(在执行节点上)
sudo systemctl start fail2ban-executor
```

#### 设置开机自启

```bash
sudo systemctl enable fail2ban-central
sudo systemctl enable fail2ban-web
sudo systemctl enable fail2ban-agent
sudo systemctl enable fail2ban-executor
```

### 命令行操作

#### 查看系统状态

```bash
# 使用监控脚本
./monitor.sh status

# 查看详细信息
./monitor.sh status -d

# 实时监控面板
./monitor.sh dashboard -w
```

#### 手动封禁IP

```bash
# 使用API
curl -X POST http://localhost:5000/api/ban \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "duration": 3600,
    "reason": "Manual ban"
  }'

# 使用Python脚本
python3 -c "
import requests
response = requests.post(
    'http://localhost:5000/api/ban',
    headers={'Authorization': 'Bearer your-api-key'},
    json={'ip': '192.168.1.100', 'duration': 3600}
)
print(response.json())
"
```

#### 查看封禁列表

```bash
# 获取当前封禁的IP
curl -H "Authorization: Bearer your-api-key" \
     http://localhost:5000/api/banned-ips

# 查看特定IP详情
curl -H "Authorization: Bearer your-api-key" \
     http://localhost:5000/api/ip/192.168.1.100
```

#### 解封IP

```bash
curl -X POST http://localhost:5000/api/unban \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

### 日志管理

#### 查看系统日志

```bash
# 查看系统日志
tail -f /var/log/fail2ban-distributed/system.log

# 查看错误日志
tail -f /var/log/fail2ban-distributed/error.log

# 使用监控脚本查看日志
./monitor.sh logs -n 100
```

#### 日志分析

```bash
# 统计封禁次数
grep "IP banned" /var/log/fail2ban-distributed/system.log | wc -l

# 查看最常被封禁的IP
grep "IP banned" /var/log/fail2ban-distributed/system.log | \
  awk '{print $NF}' | sort | uniq -c | sort -nr | head -10

# 查看攻击类型统计
grep "Attack detected" /var/log/fail2ban-distributed/system.log | \
  awk '{print $(NF-1)}' | sort | uniq -c | sort -nr
```

## Web管理界面

### 访问界面

默认访问地址：`http://your-server:8080`

默认登录信息：
- 用户名：admin
- 密码：在配置文件中设置

### 主要功能

#### 1. 仪表板

- **系统概览**: 显示总体统计信息
- **实时监控**: 实时显示攻击事件和封禁操作
- **趋势图表**: 攻击趋势和封禁趋势图
- **节点状态**: 显示所有节点的在线状态

#### 2. IP管理

- **封禁列表**: 查看当前封禁的IP列表
- **手动封禁**: 手动添加IP到封禁列表
- **批量操作**: 支持批量封禁和解封
- **白名单管理**: 管理IP白名单

#### 3. 攻击分析

- **攻击事件**: 查看最近的攻击事件
- **攻击统计**: 按类型、来源、时间统计攻击
- **地理分布**: 攻击来源的地理分布图
- **趋势分析**: 攻击趋势和模式分析

#### 4. 节点管理

- **节点列表**: 查看所有节点状态
- **性能监控**: 监控节点CPU、内存使用情况
- **日志查看**: 查看各节点的日志
- **配置管理**: 远程配置节点参数

#### 5. 系统设置

- **封禁策略**: 配置封禁规则和阈值
- **检测规则**: 管理攻击检测规则
- **通知设置**: 配置通知渠道和规则
- **用户管理**: 管理Web界面用户

### 实时功能

#### WebSocket连接

界面通过WebSocket实现实时更新：

- 实时攻击事件推送
- 实时封禁状态更新
- 实时统计数据刷新
- 实时节点状态监控

#### 自动刷新

- 统计数据每30秒自动刷新
- 节点状态每10秒检查一次
- 攻击事件实时推送
- 图表数据动态更新

## 命令行工具

### 主程序

```bash
# 启动中央控制节点
python3 main.py --mode central --config /path/to/config.yaml

# 启动代理节点
python3 main.py --mode agent --config /path/to/config.yaml

# 启动执行节点
python3 main.py --mode executor --config /path/to/config.yaml

# 启动所有组件
python3 main.py --mode all --config /path/to/config.yaml

# 调试模式
python3 main.py --mode central --log-level DEBUG
```

### 监控脚本

```bash
# 查看服务状态
./monitor.sh status

# 查看性能指标
./monitor.sh performance

# 查看日志
./monitor.sh logs -n 100

# 查看统计信息
./monitor.sh stats

# 健康检查
./monitor.sh health

# 实时监控面板
./monitor.sh dashboard -w

# JSON格式输出
./monitor.sh status -f json
```

### 测试脚本

```bash
# 运行所有测试
./test.sh

# 运行单元测试
./test.sh unit

# 运行API测试
./test.sh api --host 192.168.1.10

# 运行性能测试
./test.sh performance -v

# 运行安全测试
./test.sh security
```

### 部署脚本

```bash
# 单机部署
./quick-deploy.sh

# 集群部署
./quick-deploy.sh -m cluster -c deploy-config.yaml

# 预览部署操作
./quick-deploy.sh --dry-run

# 强制覆盖安装
./quick-deploy.sh --force
```

## 监控运维

### 系统监控

#### 服务状态监控

```bash
# 检查所有服务状态
for service in fail2ban-central fail2ban-agent fail2ban-executor fail2ban-web; do
    echo "$service: $(systemctl is-active $service)"
done

# 查看服务详细状态
sudo systemctl status fail2ban-central
```

#### 性能监控

```bash
# 查看系统资源使用
top -p $(pgrep -f "fail2ban")

# 查看内存使用
ps aux | grep -E "fail2ban|python3.*main.py" | awk '{sum+=$6} END {print "Total Memory: " sum/1024 " MB"}'

# 查看网络连接
netstat -tulpn | grep -E ":(5000|5001|8080)"
```

#### 数据库监控

```bash
# Redis监控
redis-cli info memory
redis-cli info stats

# MongoDB监控
mongo --eval "db.stats()"
mongo --eval "db.serverStatus()"
```

### 日志轮转

配置logrotate自动轮转日志：

```bash
# 创建logrotate配置
sudo tee /etc/logrotate.d/fail2ban-distributed << EOF
/var/log/fail2ban-distributed/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 fail2ban fail2ban
    postrotate
        systemctl reload fail2ban-central fail2ban-agent fail2ban-executor
    endscript
}
EOF
```

### 备份策略

#### 配置文件备份

```bash
#!/bin/bash
# 备份配置文件
BACKUP_DIR="/backup/fail2ban-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# 备份配置
cp -r /etc/fail2ban-distributed "$BACKUP_DIR/"

# 备份数据库
mongodump --out "$BACKUP_DIR/mongodb"
redis-cli --rdb "$BACKUP_DIR/redis.rdb"

# 压缩备份
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"
```

#### 自动备份

```bash
# 添加到crontab
echo "0 2 * * * /path/to/backup.sh" | crontab -
```

### 告警配置

#### 系统告警脚本

```bash
#!/bin/bash
# 系统健康检查和告警

check_service() {
    local service=$1
    if ! systemctl is-active --quiet "$service"; then
        echo "ALERT: Service $service is down" | mail -s "Fail2ban Alert" admin@example.com
    fi
}

check_service "fail2ban-central"
check_service "fail2ban-web"
check_service "redis"
check_service "mongodb"

# 检查磁盘空间
DISK_USAGE=$(df /var/log | tail -1 | awk '{print $5}' | cut -d'%' -f1)
if [ $DISK_USAGE -gt 90 ]; then
    echo "ALERT: Disk usage is ${DISK_USAGE}%" | mail -s "Disk Space Alert" admin@example.com
fi
```

## 故障排除

### 常见问题

#### 1. 服务无法启动

**症状**: systemctl start 失败

**排查步骤**:

```bash
# 查看详细错误信息
sudo journalctl -u fail2ban-central -n 50

# 检查配置文件语法
python3 -c "import yaml; yaml.safe_load(open('/etc/fail2ban-distributed/config.yaml'))"

# 检查端口占用
sudo netstat -tulpn | grep -E ":(5000|5001|8080)"

# 检查权限
sudo ls -la /opt/fail2ban/
sudo ls -la /etc/fail2ban-distributed/
```

**解决方案**:
- 修复配置文件语法错误
- 释放被占用的端口
- 修正文件权限

#### 2. 节点连接失败

**症状**: 代理或执行节点无法连接到中央服务器

**排查步骤**:

```bash
# 测试网络连通性
telnet central-server-ip 5000

# 检查防火墙
sudo iptables -L
sudo firewall-cmd --list-all

# 检查API密钥
grep "api_key" /etc/fail2ban-distributed/config.yaml

# 测试API连接
curl -H "Authorization: Bearer your-api-key" \
     http://central-server-ip:5000/api/health
```

**解决方案**:
- 配置防火墙规则
- 检查API密钥配置
- 确认网络连通性

#### 3. 数据库连接问题

**症状**: Redis或MongoDB连接失败

**排查步骤**:

```bash
# 检查Redis
sudo systemctl status redis
redis-cli ping

# 检查MongoDB
sudo systemctl status mongodb
mongo --eval "db.runCommand('ping')"

# 检查配置
grep -A 10 "database:" /etc/fail2ban-distributed/config.yaml
```

**解决方案**:
- 重启数据库服务
- 检查数据库配置
- 确认数据库权限

#### 4. 日志监控失败

**症状**: 无法监控Nginx日志文件

**排查步骤**:

```bash
# 检查日志文件权限
sudo ls -la /var/log/nginx/

# 检查配置路径
grep "log_paths" /etc/fail2ban-distributed/config.yaml

# 测试文件读取
sudo -u fail2ban tail -f /var/log/nginx/access.log
```

**解决方案**:
- 修正文件权限
- 确认日志文件路径
- 配置SELinux策略

### 调试模式

#### 启用详细日志

```bash
# 临时启用调试模式
python3 main.py --mode central --log-level DEBUG

# 修改配置文件
sed -i 's/log_level: "INFO"/log_level: "DEBUG"/' /etc/fail2ban-distributed/config.yaml
sudo systemctl restart fail2ban-central
```

#### 手动测试组件

```bash
# 测试日志解析
cd /opt/fail2ban
python3 -c "
from utils.nginx_parser import NginxLogParser
parser = NginxLogParser()
result = parser.parse_line('127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 612')
print(result)
"

# 测试攻击检测
python3 -c "
from analysis.pattern_detector import PatternDetector
detector = PatternDetector()
result = detector.detect_attack('/admin.php?id=1 union select')
print(result)
"
```

## 最佳实践

### 安全配置

#### 1. 网络安全

```bash
# 限制API访问
sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='trusted-network' port protocol='tcp' port='5000' accept"
sudo firewall-cmd --reload

# 配置SSL/TLS
# 在config.yaml中启用SSL
central:
  api:
    ssl_enabled: true
    ssl_cert: "/path/to/cert.pem"
    ssl_key: "/path/to/key.pem"
```

#### 2. 访问控制

```yaml
# 配置IP白名单
security:
  access_control:
    allowed_ips:
      - "192.168.0.0/16"
      - "10.0.0.0/8"
    denied_ips:
      - "192.168.1.100"
```

#### 3. 密钥管理

```bash
# 定期轮换API密钥
API_KEY=$(openssl rand -hex 32)
sed -i "s/api_key: .*/api_key: \"$API_KEY\"/" /etc/fail2ban-distributed/config.yaml

# 使用环境变量
export FAIL2BAN_API_KEY="your-api-key"
```

### 性能优化

#### 1. 数据库优化

```yaml
# Redis优化
central:
  database:
    redis:
      max_connections: 100
      connection_pool_size: 20

# MongoDB优化
    mongodb:
      max_pool_size: 50
      min_pool_size: 5
```

#### 2. 日志处理优化

```yaml
# 代理节点优化
agent:
  sender:
    batch_size: 500
    send_interval: 5
    compression: true
```

#### 3. 缓存策略

```yaml
# 缓存配置
performance:
  cache:
    ip_analysis_size: 10000
    pattern_cache_size: 5000
    expire_time: 1800
```

### 运维建议

#### 1. 监控策略

- 设置关键指标告警
- 定期检查系统健康状态
- 监控数据库性能
- 跟踪封禁效果

#### 2. 备份策略

- 每日备份配置文件
- 定期备份数据库
- 测试备份恢复流程
- 异地备份重要数据

#### 3. 更新策略

- 定期更新系统组件
- 测试新版本兼容性
- 制定回滚计划
- 维护更新日志

## FAQ

### Q1: 如何添加自定义攻击检测规则？

**A**: 编辑配置文件中的检测规则：

```yaml
detection:
  patterns:
    custom_patterns:
      malicious_paths:
        - "/admin/config.php"
        - "/.env"
        - "/config/database.yml"
```

### Q2: 如何调整封禁时间？

**A**: 修改封禁策略配置：

```yaml
central:
  ban_policy:
    default_ban_time: 7200  # 2小时
    max_ban_time: 86400     # 24小时
    ban_time_increment: 2   # 递增倍数
```

### Q3: 如何处理误封问题？

**A**: 
1. 添加IP到白名单
2. 手动解封IP
3. 调整检测阈值
4. 优化检测规则

```bash
# 手动解封
curl -X POST http://localhost:5000/api/unban \
  -H "Authorization: Bearer your-api-key" \
  -d '{"ip": "192.168.1.100"}'
```

### Q4: 如何扩展到更多节点？

**A**: 
1. 在新服务器上安装对应组件
2. 配置连接到中央服务器
3. 启动服务并验证连接
4. 在Web界面查看节点状态

### Q5: 如何备份和恢复系统？

**A**: 
```bash
# 备份
mongodump --out /backup/mongodb
redis-cli --rdb /backup/redis.rdb
cp -r /etc/fail2ban-distributed /backup/

# 恢复
mongorestore /backup/mongodb
redis-cli --rdb /backup/redis.rdb
cp -r /backup/fail2ban-distributed /etc/
```

### Q6: 如何优化系统性能？

**A**: 
1. 调整批处理大小
2. 优化数据库连接池
3. 启用数据压缩
4. 配置缓存策略
5. 定期清理历史数据

### Q7: 如何集成到现有监控系统？

**A**: 
1. 使用API接口获取监控数据
2. 配置Prometheus指标导出
3. 设置Grafana仪表板
4. 集成到SIEM系统

---

如需更多帮助，请参考[API文档](API.md)或联系技术支持团队。