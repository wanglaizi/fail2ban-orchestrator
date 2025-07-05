# 增强版分布式Fail2ban系统 - 快速启动指南

🚀 **欢迎使用增强版分布式Fail2ban系统！**

本指南将帮助您在5分钟内快速部署和运行系统。

## 📋 系统要求

- **Python**: 3.8+ 
- **操作系统**: Windows, Linux, macOS
- **内存**: 建议 2GB+
- **磁盘空间**: 1GB+
- **网络**: 互联网连接（用于安装依赖）

## 🎯 快速安装

### 方法一：自动安装（推荐）

```bash
# 1. 下载安装脚本
cd /path/to/your/directory
python install.py

# 2. 按照提示完成交互式安装
# 系统会自动：
# - 检查环境
# - 安装依赖
# - 生成配置
# - 创建启动脚本
```

### 方法二：手动安装

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 创建配置文件
python enhanced_fail2ban.py --create-config

# 3. 启动系统
python enhanced_fail2ban.py --config config.yaml
```

## 🚀 启动系统

### Windows
```cmd
# 使用启动脚本
scripts\start.bat

# 或命令行
python -m enhancements.enhanced_fail2ban --config config.yaml
```

### Linux/macOS
```bash
# 使用启动脚本
./scripts/start.sh

# 或命令行
python3 -m enhancements.enhanced_fail2ban --config config.yaml
```

## 🌐 访问Web管理界面

启动成功后，打开浏览器访问：

```
http://127.0.0.1:8080
```

**默认管理员账户：**
- 用户名: `admin`
- 密码: `admin123` (可在配置文件中修改)

## 📊 主要功能模块

### 1. 多租户管理
- 🏢 **租户管理**: 创建和管理多个租户
- 👥 **用户管理**: 分配不同角色和权限
- 📊 **资源配额**: 控制每个租户的资源使用

### 2. 智能告警系统
- 🔔 **动态阈值**: 自动调整告警阈值
- 🤖 **异常检测**: 基于机器学习的异常识别
- 📧 **多渠道通知**: 邮件、Webhook、Slack等

### 3. 性能监控
- 📈 **实时监控**: CPU、内存、磁盘使用率
- 🔍 **链路追踪**: 分布式请求追踪
- 📊 **性能指标**: 响应时间、吞吐量等

### 4. 安全审计
- 🛡️ **安全事件**: 记录和分析安全事件
- 📋 **合规报告**: PCI DSS、GDPR等合规报告
- 🔐 **威胁情报**: 集成外部威胁情报源

### 5. 机器学习检测
- 🧠 **智能检测**: 多种ML算法组合
- 📚 **自动学习**: 持续学习和模型优化
- 🎯 **精准识别**: 减少误报和漏报

## 🔧 快速配置

### 1. 配置日志源

编辑 `config.yaml`：

```yaml
data_sources:
  file_sources:
    - name: "nginx_access"
      type: "file"
      enabled: true
      path: "/var/log/nginx/access.log"
      format: "nginx"
    - name: "apache_access"
      type: "file"
      enabled: true
      path: "/var/log/apache2/access.log"
      format: "apache"
```

### 2. 配置邮件通知

```yaml
notification_channels:
  email:
    type: "email"
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    from_email: "your-email@gmail.com"
    to_emails: ["admin@company.com"]
    use_tls: true
```

### 3. 配置Webhook通知

```yaml
notification_channels:
  webhook:
    type: "webhook"
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    timeout: 30
```

## 📱 使用示例

### 创建租户和用户

```python
import asyncio
from enhancements.enhanced_fail2ban import EnhancedFail2banSystem

async def setup_tenant():
    # 启动系统
    system = EnhancedFail2banSystem("config.yaml")
    await system.start()
    
    # 创建租户
    tenant = await system.tenancy_manager.create_tenant(
        name="我的公司",
        description="公司安全监控"
    )
    
    # 创建用户
    user = await system.tenancy_manager.create_user(
        tenant_id=tenant.id,
        username="security_admin",
        email="admin@company.com",
        password="secure_password",
        role="TENANT_ADMIN"
    )
    
    print(f"租户创建成功: {tenant.name}")
    print(f"用户创建成功: {user.username}")

# 运行示例
asyncio.run(setup_tenant())
```

### 配置智能告警

```python
# 配置动态阈值
await system.alerting_system.configure_dynamic_threshold(
    metric="request_rate",
    base_threshold=100,
    adaptation_rate=0.1
)

# 配置异常检测
await system.alerting_system.configure_anomaly_detection(
    algorithm="isolation_forest",
    contamination=0.1
)
```

### 训练ML模型

```python
# 加载训练数据
training_data = [
    {"ip_address": "192.168.1.1", "request_count": 50, "is_attack": False},
    {"ip_address": "malicious.com", "request_count": 1000, "is_attack": True},
    # 更多训练数据...
]

# 训练模型
await system.ml_detection.train_models(training_data)

# 进行预测
prediction = await system.ml_detection.predict({
    "ip_address": "suspicious.ip",
    "request_count": 500,
    "error_rate": 0.8
})

print(f"攻击概率: {prediction.confidence}")
print(f"是否攻击: {prediction.is_attack}")
```

## 🔍 监控和调试

### 查看系统状态

```bash
# 查看日志
tail -f logs/fail2ban.log

# 查看性能指标
curl http://127.0.0.1:8080/api/monitoring/metrics

# 查看系统健康状态
curl http://127.0.0.1:8080/health
```

### Web界面功能

1. **仪表板**: 实时监控和统计信息
2. **租户管理**: 创建和管理租户
3. **用户管理**: 用户账户和权限管理
4. **告警管理**: 查看和配置告警规则
5. **安全审计**: 安全事件和合规报告
6. **系统配置**: 在线配置系统参数

## 🛠️ 常见问题

### Q: 启动时提示模块导入错误？
A: 确保已安装所有依赖：`pip install -r requirements.txt`

### Q: Web界面无法访问？
A: 检查防火墙设置，确保端口8080未被占用

### Q: 邮件通知不工作？
A: 检查SMTP配置，确保使用应用专用密码（如Gmail）

### Q: 日志文件无法读取？
A: 确保程序有读取日志文件的权限

### Q: 性能监控数据不准确？
A: 检查系统时间同步，确保监控间隔配置合理

## 📚 进阶配置

### 高可用部署

```yaml
clustering:
  enabled: true
  nodes:
    - host: "node1.example.com"
      port: 8080
    - host: "node2.example.com"
      port: 8080
  load_balancer:
    algorithm: "round_robin"
```

### Redis缓存配置

```yaml
caching:
  type: "redis"
  redis:
    host: "localhost"
    port: 6379
    db: 0
    password: "your-redis-password"
```

### MongoDB数据库配置

```yaml
database:
  mongodb:
    enabled: true
    host: "localhost"
    port: 27017
    database: "fail2ban"
    username: "fail2ban_user"
    password: "secure_password"
```

## 🔄 系统维护

### 备份配置

```bash
# 手动备份
python enhanced_fail2ban.py --backup

# 自动备份（在config.yaml中配置）
backup:
  enabled: true
  schedule: "0 2 * * *"  # 每天凌晨2点
  retention_days: 30
```

### 更新系统

```bash
# 停止系统
python enhanced_fail2ban.py --stop

# 更新代码
git pull origin main

# 安装新依赖
pip install -r requirements.txt

# 重启系统
python enhanced_fail2ban.py --config config.yaml
```

### 性能优化

1. **调整监控间隔**: 根据系统负载调整监控频率
2. **优化ML模型**: 定期重新训练模型
3. **清理历史数据**: 定期清理过期的日志和监控数据
4. **调整缓存策略**: 根据内存使用情况调整缓存配置

## 📞 技术支持

- **文档**: [完整文档](README.md)
- **示例配置**: [example_config.yaml](example_config.yaml)
- **问题反馈**: [GitHub Issues](https://github.com/wanglaizi/fail2ban-orchestrator/issues)
- **社区讨论**: [GitHub Discussions](https://github.com/wanglaizi/fail2ban-orchestrator/discussions)

## 🎉 下一步

恭喜！您已经成功部署了增强版Fail2ban系统。现在您可以：

1. 📊 **监控仪表板**: 查看实时安全状态
2. 🔧 **自定义规则**: 根据业务需求配置检测规则
3. 📧 **配置通知**: 设置告警通知渠道
4. 🤖 **训练模型**: 使用您的数据训练ML模型
5. 👥 **邀请团队**: 创建用户账户，邀请团队成员

---

**🛡️ 保护您的系统，从现在开始！**

如有任何问题，请查看[完整文档](README.md)或联系技术支持。