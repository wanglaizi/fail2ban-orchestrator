# 分布式Fail2ban系统增强功能

本文档详细介绍分布式Fail2ban系统的增强功能模块，包括智能告警、性能监控、安全审计、机器学习检测、图形化配置、多数据源支持和多租户管理等高级功能。

> **注意**: 基础系统概述和快速安装请参考主项目 [README.md](../README.md)。本文档专注于增强功能的详细配置和使用。

## 目录

- [增强功能概述](#增强功能概述)
- [功能模块详解](#功能模块详解)
- [高级配置](#高级配置)
- [开发指南](#开发指南)
- [API参考](#api参考)
- [集成示例](#集成示例)
- [最佳实践](#最佳实践)
- [故障排除](#故障排除)

## 增强功能概述

增强功能模块在核心Fail2ban系统基础上提供企业级功能：

```
┌─────────────────────────────────────────────────────────────┐
│                    增强功能层                                 │
├─────────────────────────────────────────────────────────────┤
│  多租户管理  │  智能告警  │  性能监控  │  安全审计  │  ML检测   │
├─────────────────────────────────────────────────────────────┤
│              多数据源和通知渠道管理                           │
├─────────────────────────────────────────────────────────────┤
│                    核心Fail2ban引擎                          │
└─────────────────────────────────────────────────────────────┘
```

## 功能模块详解

### 1. 智能告警和动态阈值 (`intelligent_alerting.py`)

**功能特性：**
- 动态阈值调整
- 异常检测算法
- 告警抑制和去重
- 多级告警严重性
- 灵活的通知规则

**核心类：**
- `IntelligentAlertingSystem`: 主要告警系统
- `DynamicThreshold`: 动态阈值管理
- `AnomalyDetector`: 异常检测器

### 2. 性能监控和链路追踪 (`performance_monitoring.py`)

**功能特性：**
- 分布式链路追踪
- 性能指标收集
- 实时监控告警
- 性能数据导出
- 自动性能优化建议

**核心类：**
- `PerformanceMonitor`: 性能监控主类
- `DistributedTracer`: 分布式追踪器
- `PerformanceCollector`: 性能数据收集器

### 3. 安全审计功能 (`security_auditing.py`)

**功能特性：**
- 安全事件记录
- 威胁情报集成
- 合规性报告
- 安全事件分析
- 加密存储

**核心类：**
- `SecurityAuditingSystem`: 安全审计主系统
- `ThreatIntelligence`: 威胁情报管理
- `ComplianceReporter`: 合规报告生成器

### 4. 机器学习攻击检测 (`ml_attack_detection.py`)

**功能特性：**
- 多种ML模型支持
- 特征工程
- 模型训练和更新
- 集成学习
- 攻击模式识别

**核心类：**
- `MLAttackDetectionSystem`: ML检测主系统
- `FeatureExtractor`: 特征提取器
- `EnsembleModel`: 集成模型

### 5. 图形化配置界面 (`gui_config_interface.py`)

**功能特性：**
- Web界面配置
- 配置验证
- 配置导入导出
- 实时配置更新
- 配置备份恢复

**核心类：**
- `GUIConfigInterface`: Web配置界面
- `ConfigValidator`: 配置验证器
- `ConfigManager`: 配置管理器

### 6. 多数据源和通知渠道 (`multi_datasource_notification.py`)

**功能特性：**
- 多种数据源支持
- 多种通知渠道
- 数据源健康检查
- 通知渠道测试
- 统一数据格式

**核心类：**
- `MultiDataSourceManager`: 多数据源管理器
- `FileDataSource`: 文件数据源
- `RedisDataSource`: Redis数据源
- `EmailNotificationChannel`: 邮件通知
- `SlackNotificationChannel`: Slack通知

### 7. 多租户支持 (`multi_tenancy.py`)

**功能特性：**
- 租户隔离
- 用户权限管理
- 资源配额控制
- 会话管理
- 数据隔离

**核心类：**
- `MultiTenancyManager`: 多租户管理器
- `AuthenticationManager`: 认证管理器
- `AuthorizationManager`: 授权管理器
- `ResourceQuotaManager`: 配额管理器

## 高级配置

> **前置条件**: 请确保已按照主 [README.md](../README.md) 完成基础系统安装。

### 增强功能配置

创建配置文件 `config.yaml`：

```yaml
# 系统配置
system:
  debug: false
  log_level: INFO
  secret_key: "your-secret-key-here"

# 多租户配置
multi_tenancy:
  enabled: true
  storage:
    type: sqlite
    db_path: tenants.db
  admin_password: admin123
  default_quota:
    max_banned_ips: 1000
    max_rules: 50
    max_users: 5
    max_api_requests_per_hour: 5000
    max_log_retention_days: 30
    max_storage_mb: 500
    max_concurrent_sessions: 5

# 智能告警配置
intelligent_alerting:
  enabled: true
  anomaly_detection:
    algorithm: isolation_forest
    contamination: 0.1
    window_size: 100
  dynamic_thresholds:
    enabled: true
    adaptation_rate: 0.1
    min_samples: 50
  alert_suppression:
    enabled: true
    time_window: 300
    max_alerts_per_window: 5

# 性能监控配置
performance_monitoring:
  enabled: true
  collection_interval: 60
  trace_sampling_rate: 0.1
  thresholds:
    cpu_usage: 80
    memory_usage: 85
    response_time: 1000
    error_rate: 5

# 安全审计配置
security_auditing:
  enabled: true
  encryption_key: "your-encryption-key-here"
  threat_intelligence:
    enabled: true
    feeds:
      - name: "malware_ips"
        url: "https://example.com/malware-ips.txt"
        format: "text"
        update_interval: 3600
  compliance:
    standards: ["PCI_DSS", "GDPR"]
    report_interval: 86400

# ML攻击检测配置
ml_attack_detection:
  enabled: true
  models:
    - name: "random_forest"
      type: "RandomForest"
      enabled: true
      config:
        n_estimators: 100
        max_depth: 10
    - name: "anomaly_detection"
      type: "AnomalyDetection"
      enabled: true
      config:
        contamination: 0.1
  feature_extraction:
    time_windows: [60, 300, 3600]
    behavioral_features: true
  training:
    auto_retrain: true
    retrain_interval: 86400
    min_samples: 1000

# 数据源配置
data_sources:
  nginx_access:
    type: file
    enabled: true
    file_path: /var/log/nginx/access.log
    log_format: combined
    encoding: utf-8
    tail_mode: true
  
  redis_cache:
    type: redis
    enabled: true
    host: localhost
    port: 6379
    db: 0
    key_prefix: "fail2ban:logs"
    max_entries: 10000

# 通知渠道配置
notification_channels:
  email_admin:
    type: email
    enabled: true
    smtp_server: smtp.gmail.com
    smtp_port: 587
    username: admin@example.com
    password: your-email-password
    to_emails:
      - admin@example.com
    rate_limit: 300
  
  slack_alerts:
    type: slack
    enabled: true
    webhook_url: https://hooks.slack.com/services/...
    channel: "#security"
    username: "Fail2ban Bot"
    rate_limit: 60
  
  dingtalk_alerts:
    type: dingtalk
    enabled: true
    webhook_url: https://oapi.dingtalk.com/robot/send?access_token=...
    secret: your-dingtalk-secret
    rate_limit: 60

# Web界面配置
web_interface:
  host: 0.0.0.0
  port: 8080
  debug: false
  cors_origins:
    - "http://localhost:3000"
    - "https://yourdomain.com"
```

## 开发指南

### 快速集成

增强功能采用模块化设计，可以选择性启用所需功能：

### 系统初始化

```python
import asyncio
from enhancements.multi_tenancy import MultiTenancyManager
from enhancements.intelligent_alerting import IntelligentAlertingSystem
from enhancements.performance_monitoring import PerformanceMonitor
from enhancements.security_auditing import SecurityAuditingSystem
from enhancements.ml_attack_detection import MLAttackDetectionSystem
from enhancements.multi_datasource_notification import MultiDataSourceManager
from enhancements.gui_config_interface import GUIConfigInterface
from utils.config import ConfigManager

async def main():
    # 加载配置
    config_manager = ConfigManager()
    config = config_manager.load_config('config.yaml')
    
    # 初始化多租户管理
    tenancy_manager = MultiTenancyManager(config['multi_tenancy'])
    await tenancy_manager.initialize()
    await tenancy_manager.start_background_tasks()
    
    # 初始化智能告警
    alerting_system = IntelligentAlertingSystem(config['intelligent_alerting'])
    await alerting_system.initialize()
    
    # 初始化性能监控
    performance_monitor = PerformanceMonitor(config['performance_monitoring'])
    await performance_monitor.start_monitoring()
    
    # 初始化安全审计
    security_auditing = SecurityAuditingSystem(config['security_auditing'])
    await security_auditing.initialize()
    
    # 初始化ML检测
    ml_detection = MLAttackDetectionSystem(config['ml_attack_detection'])
    await ml_detection.initialize()
    
    # 初始化多数据源管理
    datasource_manager = MultiDataSourceManager({
        'data_sources': config['data_sources'],
        'notification_channels': config['notification_channels']
    })
    await datasource_manager.start_monitoring()
    
    # 启动Web界面
    gui_interface = GUIConfigInterface(config['web_interface'])
    await gui_interface.start_server()
    
    print("分布式Fail2ban系统已启动")
    
    # 保持运行
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("正在关闭系统...")
        await datasource_manager.stop_monitoring()
        await performance_monitor.stop_monitoring()
        print("系统已关闭")

if __name__ == "__main__":
    asyncio.run(main())
```

### 创建租户和用户

```python
# 创建租户
tenant = await tenancy_manager.create_tenant(
    name="示例公司",
    description="示例租户",
    quota=ResourceQuota(
        max_banned_ips=2000,
        max_rules=100,
        max_users=10
    )
)

# 创建用户
user = await tenancy_manager.create_user(
    tenant_id=tenant.id,
    username="admin",
    email="admin@example.com",
    password="secure_password",
    role=UserRole.TENANT_ADMIN
)

# 用户登录
session = await tenancy_manager.login(
    tenant_id=tenant.id,
    username="admin",
    password="secure_password",
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0..."
)
```

### 配置智能告警

```python
# 添加告警规则
await alerting_system.add_alert_rule(
    name="高频攻击检测",
    condition={
        "metric": "attack_count",
        "operator": ">",
        "threshold": 100,
        "time_window": 300
    },
    severity=AlertSeverity.HIGH,
    actions=["ban_ip", "send_notification"]
)

# 处理事件
event = {
    "timestamp": datetime.now(),
    "source": "nginx",
    "ip_address": "192.168.1.100",
    "attack_type": "brute_force",
    "severity": "high"
}

await alerting_system.process_event(event)
```

### 使用ML检测

```python
# 训练模型
training_data = [
    {
        "ip_address": "192.168.1.100",
        "request_count": 1000,
        "error_rate": 0.8,
        "user_agents": ["bot1", "bot2"],
        "is_attack": True
    },
    # 更多训练数据...
]

await ml_detection.train_models(training_data)

# 预测攻击
request_data = {
    "ip_address": "10.0.0.1",
    "request_count": 500,
    "error_rate": 0.9,
    "user_agents": ["suspicious_bot"]
}

prediction = await ml_detection.predict(request_data)
if prediction.is_attack:
    print(f"检测到攻击，置信度: {prediction.confidence}")
```

## API参考

> **完整API文档**: 详细的API文档请参考 [API_REFERENCE.md](API_REFERENCE.md)

### 核心API概览

### 认证API

#### POST /api/auth/login
用户登录

**请求体：**
```json
{
    "tenant_id": "tenant-uuid",
    "username": "admin",
    "password": "password"
}
```

**响应：**
```json
{
    "success": true,
    "token": "session-token",
    "user": {
        "id": "user-uuid",
        "username": "admin",
        "role": "tenant_admin",
        "permissions": ["ip:ban", "ip:unban"]
    }
}
```

#### POST /api/auth/logout
用户登出

**请求头：**
```
Authorization: Bearer session-token
```

### 租户管理API

#### GET /api/tenants
获取租户列表（仅超级管理员）

#### POST /api/tenants
创建租户

**请求体：**
```json
{
    "name": "新租户",
    "description": "租户描述",
    "quota": {
        "max_banned_ips": 1000,
        "max_rules": 50,
        "max_users": 5
    }
}
```

#### GET /api/tenants/{tenant_id}
获取租户详情

#### PUT /api/tenants/{tenant_id}
更新租户信息

#### DELETE /api/tenants/{tenant_id}
删除租户

### 用户管理API

#### GET /api/users
获取当前租户用户列表

#### POST /api/users
创建用户

**请求体：**
```json
{
    "username": "newuser",
    "email": "user@example.com",
    "password": "password",
    "role": "operator"
}
```

#### GET /api/users/{user_id}
获取用户详情

#### PUT /api/users/{user_id}
更新用户信息

#### DELETE /api/users/{user_id}
删除用户

### IP管理API

#### GET /api/ips/banned
获取封禁IP列表

#### POST /api/ips/ban
封禁IP

**请求体：**
```json
{
    "ip_address": "192.168.1.100",
    "reason": "暴力破解攻击",
    "duration": 3600
}
```

#### DELETE /api/ips/ban/{ip_address}
解封IP

### 告警API

#### GET /api/alerts
获取告警列表

#### GET /api/alerts/{alert_id}
获取告警详情

#### PUT /api/alerts/{alert_id}/acknowledge
确认告警

### 监控API

#### GET /api/monitoring/metrics
获取监控指标

#### GET /api/monitoring/traces
获取链路追踪数据

#### GET /api/monitoring/health
获取系统健康状态

### 配置API

#### GET /api/config
获取配置信息

#### PUT /api/config
更新配置

#### POST /api/config/validate
验证配置

#### GET /api/config/export
导出配置

#### POST /api/config/import
导入配置

## 集成示例

### 完整的集成示例

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统集成示例
"""

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path

# 导入增强功能模块
from enhancements.multi_tenancy import (
    MultiTenancyManager, UserRole, Permission, ResourceQuota
)
from enhancements.intelligent_alerting import (
    IntelligentAlertingSystem, AlertSeverity, AlertType
)
from enhancements.performance_monitoring import (
    PerformanceMonitor, get_performance_monitor
)
from enhancements.security_auditing import (
    SecurityAuditingSystem, SecurityEventType, SecurityLevel
)
from enhancements.ml_attack_detection import (
    MLAttackDetectionSystem
)
from enhancements.multi_datasource_notification import (
    MultiDataSourceManager, NotificationMessage
)
from enhancements.gui_config_interface import (
    GUIConfigInterface
)

class EnhancedFail2banSystem:
    """增强版Fail2ban系统"""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        
        # 初始化各个管理器
        self.tenancy_manager = None
        self.alerting_system = None
        self.performance_monitor = None
        self.security_auditing = None
        self.ml_detection = None
        self.datasource_manager = None
        self.gui_interface = None
        
        self.is_running = False
    
    def _load_config(self) -> dict:
        """加载配置文件"""
        if self.config_path.suffix.lower() == '.yaml':
            import yaml
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        else:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    
    async def initialize(self) -> None:
        """初始化系统"""
        print("正在初始化增强版Fail2ban系统...")
        
        # 初始化多租户管理
        if self.config.get('multi_tenancy', {}).get('enabled', False):
            print("初始化多租户管理...")
            self.tenancy_manager = MultiTenancyManager(self.config['multi_tenancy'])
            await self.tenancy_manager.initialize()
            await self.tenancy_manager.start_background_tasks()
        
        # 初始化智能告警
        if self.config.get('intelligent_alerting', {}).get('enabled', False):
            print("初始化智能告警系统...")
            self.alerting_system = IntelligentAlertingSystem(self.config['intelligent_alerting'])
            await self.alerting_system.initialize()
        
        # 初始化性能监控
        if self.config.get('performance_monitoring', {}).get('enabled', False):
            print("初始化性能监控...")
            self.performance_monitor = PerformanceMonitor(self.config['performance_monitoring'])
            await self.performance_monitor.start_monitoring()
        
        # 初始化安全审计
        if self.config.get('security_auditing', {}).get('enabled', False):
            print("初始化安全审计...")
            self.security_auditing = SecurityAuditingSystem(self.config['security_auditing'])
            await self.security_auditing.initialize()
        
        # 初始化ML检测
        if self.config.get('ml_attack_detection', {}).get('enabled', False):
            print("初始化机器学习攻击检测...")
            self.ml_detection = MLAttackDetectionSystem(self.config['ml_attack_detection'])
            await self.ml_detection.initialize()
        
        # 初始化多数据源管理
        if (self.config.get('data_sources') or self.config.get('notification_channels')):
            print("初始化多数据源和通知管理...")
            self.datasource_manager = MultiDataSourceManager({
                'data_sources': self.config.get('data_sources', {}),
                'notification_channels': self.config.get('notification_channels', {})
            })
            await self.datasource_manager.start_monitoring()
        
        # 初始化Web界面
        if self.config.get('web_interface', {}).get('enabled', True):
            print("初始化Web管理界面...")
            self.gui_interface = GUIConfigInterface(self.config.get('web_interface', {}))
            # Web界面将在start()方法中启动
        
        print("系统初始化完成")
    
    async def start(self) -> None:
        """启动系统"""
        if self.is_running:
            return
        
        await self.initialize()
        
        # 启动Web界面
        if self.gui_interface:
            await self.gui_interface.start_server()
        
        self.is_running = True
        print("增强版Fail2ban系统已启动")
        
        # 运行示例任务
        await self._run_demo_tasks()
    
    async def stop(self) -> None:
        """停止系统"""
        if not self.is_running:
            return
        
        print("正在停止系统...")
        
        if self.datasource_manager:
            await self.datasource_manager.stop_monitoring()
        
        if self.performance_monitor:
            await self.performance_monitor.stop_monitoring()
        
        self.is_running = False
        print("系统已停止")
    
    async def _run_demo_tasks(self) -> None:
        """运行演示任务"""
        print("\n=== 运行演示任务 ===")
        
        # 演示多租户功能
        if self.tenancy_manager:
            await self._demo_multi_tenancy()
        
        # 演示智能告警
        if self.alerting_system:
            await self._demo_intelligent_alerting()
        
        # 演示ML检测
        if self.ml_detection:
            await self._demo_ml_detection()
        
        # 演示安全审计
        if self.security_auditing:
            await self._demo_security_auditing()
        
        # 演示通知功能
        if self.datasource_manager:
            await self._demo_notifications()
    
    async def _demo_multi_tenancy(self) -> None:
        """演示多租户功能"""
        print("\n--- 多租户功能演示 ---")
        
        # 创建演示租户
        tenant = await self.tenancy_manager.create_tenant(
            name="演示公司",
            description="用于演示的测试租户",
            quota=ResourceQuota(
                max_banned_ips=500,
                max_rules=25,
                max_users=3
            )
        )
        
        if tenant:
            print(f"✓ 已创建租户: {tenant.name} ({tenant.id})")
            
            # 创建演示用户
            user = await self.tenancy_manager.create_user(
                tenant_id=tenant.id,
                username="demo_admin",
                email="demo@example.com",
                password="demo123",
                role=UserRole.TENANT_ADMIN
            )
            
            if user:
                print(f"✓ 已创建用户: {user.username} ({user.id})")
                
                # 用户登录
                session = await self.tenancy_manager.login(
                    tenant_id=tenant.id,
                    username="demo_admin",
                    password="demo123",
                    ip_address="127.0.0.1",
                    user_agent="Demo Client"
                )
                
                if session:
                    print(f"✓ 用户登录成功，会话令牌: {session.token[:20]}...")
                    
                    # 验证权限
                    has_ban_permission = self.tenancy_manager.check_permission(
                        user, Permission.IP_BAN
                    )
                    print(f"✓ 用户封禁IP权限: {has_ban_permission}")
                    
                    # 获取租户统计
                    stats = await self.tenancy_manager.get_tenant_statistics(tenant.id)
                    print(f"✓ 租户统计: 用户数={stats['user_count']}, 活跃用户数={stats['active_user_count']}")
    
    async def _demo_intelligent_alerting(self) -> None:
        """演示智能告警功能"""
        print("\n--- 智能告警功能演示 ---")
        
        # 添加告警规则
        await self.alerting_system.add_alert_rule(
            name="演示高频攻击检测",
            condition={
                "metric": "attack_count",
                "operator": ">",
                "threshold": 10,
                "time_window": 60
            },
            severity=AlertSeverity.HIGH,
            actions=["log", "notify"]
        )
        print("✓ 已添加告警规则: 演示高频攻击检测")
        
        # 模拟攻击事件
        for i in range(15):
            event = {
                "timestamp": datetime.now(),
                "source": "demo_source",
                "ip_address": "192.168.1.100",
                "attack_type": "brute_force",
                "severity": "medium",
                "details": f"模拟攻击事件 #{i+1}"
            }
            
            await self.alerting_system.process_event(event)
        
        print("✓ 已处理15个模拟攻击事件")
        
        # 获取告警统计
        stats = self.alerting_system.get_statistics()
        print(f"✓ 告警统计: 总事件={stats['total_events']}, 总告警={stats['total_alerts']}")
    
    async def _demo_ml_detection(self) -> None:
        """演示ML检测功能"""
        print("\n--- 机器学习检测功能演示 ---")
        
        # 准备训练数据
        training_data = [
            # 正常请求
            {
                "ip_address": "192.168.1.10",
                "request_count": 50,
                "error_rate": 0.02,
                "avg_response_time": 200,
                "unique_paths": 10,
                "user_agents": ["Mozilla/5.0"],
                "is_attack": False
            },
            # 攻击请求
            {
                "ip_address": "10.0.0.1",
                "request_count": 1000,
                "error_rate": 0.8,
                "avg_response_time": 50,
                "unique_paths": 2,
                "user_agents": ["bot", "scanner"],
                "is_attack": True
            }
        ] * 100  # 重复数据以满足训练要求
        
        # 训练模型
        print("正在训练ML模型...")
        await self.ml_detection.train_models(training_data)
        print("✓ ML模型训练完成")
        
        # 测试预测
        test_data = {
            "ip_address": "suspicious.ip.com",
            "request_count": 800,
            "error_rate": 0.7,
            "avg_response_time": 30,
            "unique_paths": 1,
            "user_agents": ["malicious_bot"]
        }
        
        prediction = await self.ml_detection.predict(test_data)
        print(f"✓ ML预测结果: 是否攻击={prediction.is_attack}, 置信度={prediction.confidence:.2f}")
        
        # 获取模型统计
        stats = self.ml_detection.get_statistics()
        print(f"✓ ML统计: 总预测={stats['total_predictions']}, 准确率={stats.get('accuracy', 0):.2f}")
    
    async def _demo_security_auditing(self) -> None:
        """演示安全审计功能"""
        print("\n--- 安全审计功能演示 ---")
        
        # 记录安全事件
        events = [
            {
                "event_type": SecurityEventType.LOGIN_SUCCESS,
                "level": SecurityLevel.INFO,
                "source_ip": "192.168.1.100",
                "user_id": "demo_user",
                "description": "用户成功登录",
                "metadata": {"user_agent": "Mozilla/5.0"}
            },
            {
                "event_type": SecurityEventType.IP_BANNED,
                "level": SecurityLevel.WARNING,
                "source_ip": "10.0.0.1",
                "description": "IP地址被封禁",
                "metadata": {"reason": "暴力破解攻击"}
            },
            {
                "event_type": SecurityEventType.ATTACK_DETECTED,
                "level": SecurityLevel.HIGH,
                "source_ip": "malicious.com",
                "description": "检测到SQL注入攻击",
                "metadata": {"attack_type": "sql_injection", "payload": "' OR 1=1--"}
            }
        ]
        
        for event_data in events:
            await self.security_auditing.log_security_event(**event_data)
        
        print(f"✓ 已记录{len(events)}个安全事件")
        
        # 查询安全事件
        recent_events = await self.security_auditing.query_events(
            start_time=datetime.now() - timedelta(hours=1),
            limit=10
        )
        print(f"✓ 查询到{len(recent_events)}个最近的安全事件")
        
        # 生成合规报告
        report = await self.security_auditing.generate_compliance_report(
            standard="PCI_DSS",
            start_time=datetime.now() - timedelta(days=1),
            end_time=datetime.now()
        )
        print(f"✓ 生成PCI DSS合规报告: {len(report.get('events', []))}个相关事件")
    
    async def _demo_notifications(self) -> None:
        """演示通知功能"""
        print("\n--- 通知功能演示 ---")
        
        # 发送测试通知
        test_message = NotificationMessage(
            title="系统演示通知",
            content="这是一条来自增强版Fail2ban系统的演示通知消息。\n\n系统运行正常，所有功能模块已成功初始化。",
            level="info",
            timestamp=datetime.now(),
            source="demo_system",
            tags=["demo", "test", "system"],
            metadata={
                "version": "2.0.0",
                "environment": "demo"
            }
        )
        
        results = await self.datasource_manager.send_notification_to_all_channels(test_message)
        success_count = sum(1 for success in results.values() if success)
        print(f"✓ 通知发送结果: {success_count}/{len(results)}个渠道发送成功")
        
        # 获取统计信息
        stats = self.datasource_manager.get_statistics()
        print(f"✓ 数据源统计: {stats['data_sources']['total']}个数据源, {stats['notification_channels']['total']}个通知渠道")


async def main():
    """主函数"""
    # 创建示例配置
    config = {
        "system": {
            "debug": True,
            "log_level": "INFO"
        },
        "multi_tenancy": {
            "enabled": True,
            "storage": {
                "type": "sqlite",
                "db_path": "demo_tenants.db"
            },
            "admin_password": "admin123",
            "default_quota": {
                "max_banned_ips": 1000,
                "max_rules": 50,
                "max_users": 5
            }
        },
        "intelligent_alerting": {
            "enabled": True,
            "anomaly_detection": {
                "algorithm": "isolation_forest",
                "contamination": 0.1
            }
        },
        "performance_monitoring": {
            "enabled": True,
            "collection_interval": 60
        },
        "security_auditing": {
            "enabled": True,
            "encryption_key": "demo-encryption-key-32-chars-long"
        },
        "ml_attack_detection": {
            "enabled": True,
            "models": [
                {
                    "name": "random_forest",
                    "type": "RandomForest",
                    "enabled": True
                }
            ]
        },
        "notification_channels": {
            "console": {
                "type": "webhook",
                "enabled": True,
                "webhook_url": "http://httpbin.org/post",
                "rate_limit": 60
            }
        },
        "web_interface": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8080
        }
    }
    
    # 保存配置到临时文件
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_path = f.name
    
    # 创建并启动系统
    system = EnhancedFail2banSystem(config_path)
    
    try:
        await system.start()
        
        print("\n=== 系统运行中 ===")
        print("Web管理界面: http://127.0.0.1:8080")
        print("按 Ctrl+C 停止系统")
        
        # 保持运行
        while system.is_running:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("\n收到停止信号...")
    finally:
        await system.stop()
        # 清理临时配置文件
        Path(config_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
```

## 最佳实践

### 1. 多租户管理

- **资源隔离**: 确保租户间数据完全隔离
- **配额管理**: 合理设置资源配额，防止资源滥用
- **权限控制**: 实施最小权限原则
- **会话管理**: 设置合理的会话超时时间

### 2. 智能告警优化

- **阈值调优**: 根据历史数据动态调整告警阈值
- **告警抑制**: 避免告警风暴，设置合理的抑制规则
- **分级处理**: 根据严重程度设置不同的处理流程
- **误报分析**: 定期分析误报原因并优化规则

### 3. 机器学习模型

- **数据质量**: 确保训练数据的质量和多样性
- **模型更新**: 定期重新训练模型以适应新的攻击模式
- **特征工程**: 持续优化特征提取算法
- **模型评估**: 建立完善的模型评估体系

### 4. 性能监控

- **指标选择**: 选择关键性能指标进行监控
- **采样策略**: 合理设置采样率，平衡性能和准确性
- **存储优化**: 定期清理历史监控数据
- **告警联动**: 将性能监控与智能告警系统联动

## 故障排除

### 增强功能特定问题

#### 1. 多租户功能问题

**问题**: 租户数据泄露
```
症状: 用户能看到其他租户的数据
原因: 数据隔离配置错误
解决: 检查tenant_id过滤逻辑
```

**问题**: 配额限制不生效
```
症状: 用户超出配额仍能操作
原因: 配额检查逻辑缺失
解决: 验证ResourceQuotaManager配置
```

#### 2. 智能告警问题

**问题**: 告警延迟过高
```
症状: 攻击发生后很久才收到告警
原因: 事件处理队列积压
解决: 增加处理线程或优化算法
```

**问题**: 误报率过高
```
症状: 大量正常行为被误报为攻击
原因: 阈值设置过于敏感
解决: 调整动态阈值参数或增加白名单
```

#### 3. ML检测问题

**问题**: 模型预测准确率低
```
症状: 攻击检测效果差
原因: 训练数据不足或特征选择不当
解决: 增加训练样本，优化特征工程
```

**问题**: 模型训练失败
```
症状: 训练过程中出现异常
原因: 数据格式错误或内存不足
解决: 检查数据预处理和资源配置
```

#### 4. 性能监控问题

**问题**: 监控数据丢失
```
症状: 监控图表出现空白
原因: 数据收集器异常或存储问题
解决: 检查collector状态和存储连接
```

### 调试工具

#### 启用详细日志
```python
import logging
logging.getLogger('enhancements').setLevel(logging.DEBUG)
```

#### 健康检查
```python
# 检查各模块状态
health_status = await system.get_health_status()
print(health_status)
```

#### 性能分析
```python
# 获取性能指标
metrics = await performance_monitor.get_current_metrics()
print(f"CPU: {metrics['cpu_usage']}%")
print(f"Memory: {metrics['memory_usage']}%")
```

## 贡献指南

增强功能模块的贡献请遵循主项目的贡献指南，详见主 [README.md](../README.md#贡献指南)。

### 增强功能开发规范

- **模块化设计**: 每个增强功能应独立可配置
- **向后兼容**: 确保不影响核心系统功能
- **文档完整**: 提供详细的配置说明和使用示例
- **测试覆盖**: 包含单元测试和集成测试

---

**注意**: 增强功能模块仍在持续开发中，生产环境使用前请进行充分测试和安全评估。更多信息请参考主项目文档。