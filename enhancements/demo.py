#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版分布式Fail2ban系统演示脚本

这个脚本演示了系统的所有主要功能，包括：
- 多租户管理
- 智能告警和动态阈值
- 性能监控和链路追踪
- 安全审计功能
- 机器学习攻击检测
- 多数据源和通知渠道
- Web管理界面

作者: Fail2ban开发团队
版本: 2.0.0
许可: MIT License
"""

import asyncio
import json
import random
import time
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any
from pathlib import Path

# 导入系统模块
try:
    from enhanced_fail2ban import EnhancedFail2banSystem, create_default_config
    from multi_tenancy import UserRole, Permission, ResourceQuota
    from intelligent_alerting import AlertSeverity, AlertType
    from security_auditing import SecurityEventType, SecurityLevel
    from multi_datasource_notification import NotificationMessage
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请确保已正确安装所有依赖包")
    exit(1)


class Colors:
    """终端颜色常量"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


class EnhancedFail2banDemo:
    """
    增强版Fail2ban系统演示类
    
    提供完整的功能演示和测试。
    """
    
    def __init__(self, config_path: str = "demo_config.yaml"):
        """
        初始化演示系统
        
        Args:
            config_path: 配置文件路径
        """
        self.config_path = config_path
        self.system: EnhancedFail2banSystem = None
        self.demo_data = self._generate_demo_data()
        
        # 演示统计
        self.demo_stats = {
            'tenants_created': 0,
            'users_created': 0,
            'alerts_generated': 0,
            'events_processed': 0,
            'ml_predictions': 0,
            'notifications_sent': 0
        }
    
    def _generate_demo_data(self) -> Dict[str, Any]:
        """
        生成演示数据
        
        Returns:
            演示数据字典
        """
        return {
            'tenants': [
                {
                    'name': '科技公司A',
                    'description': '一家专注于AI技术的科技公司',
                    'quota': ResourceQuota(
                        max_banned_ips=1000,
                        max_rules=50,
                        max_users=10,
                        max_storage_mb=200
                    )
                },
                {
                    'name': '电商平台B',
                    'description': '大型电子商务平台',
                    'quota': ResourceQuota(
                        max_banned_ips=5000,
                        max_rules=100,
                        max_users=25,
                        max_storage_mb=500
                    )
                },
                {
                    'name': '金融机构C',
                    'description': '提供在线金融服务的机构',
                    'quota': ResourceQuota(
                        max_banned_ips=2000,
                        max_rules=75,
                        max_users=15,
                        max_storage_mb=300
                    )
                }
            ],
            'users': [
                {'username': 'tech_admin', 'email': 'admin@techcompany.com', 'role': UserRole.TENANT_ADMIN},
                {'username': 'security_analyst', 'email': 'security@techcompany.com', 'role': UserRole.SECURITY_ANALYST},
                {'username': 'ecommerce_admin', 'email': 'admin@ecommerce.com', 'role': UserRole.TENANT_ADMIN},
                {'username': 'finance_admin', 'email': 'admin@finance.com', 'role': UserRole.TENANT_ADMIN},
                {'username': 'auditor', 'email': 'audit@finance.com', 'role': UserRole.AUDITOR}
            ],
            'attack_scenarios': [
                {
                    'name': 'SQL注入攻击',
                    'ip': '192.168.100.10',
                    'requests': [
                        "GET /login.php?id=1' OR '1'='1 HTTP/1.1",
                        "POST /search.php payload='; DROP TABLE users; --",
                        "GET /admin.php?user=admin' UNION SELECT password FROM users--"
                    ],
                    'severity': 'high'
                },
                {
                    'name': '暴力破解攻击',
                    'ip': '10.0.0.50',
                    'requests': [
                        "POST /login username=admin&password=123456",
                        "POST /login username=admin&password=password",
                        "POST /login username=admin&password=admin123",
                        "POST /login username=admin&password=qwerty"
                    ] * 50,  # 重复多次模拟暴力破解
                    'severity': 'medium'
                },
                {
                    'name': 'DDoS攻击',
                    'ip': '203.0.113.100',
                    'requests': ["GET / HTTP/1.1"] * 1000,  # 大量请求
                    'severity': 'critical'
                },
                {
                    'name': 'XSS攻击',
                    'ip': '172.16.0.25',
                    'requests': [
                        "GET /search?q=<script>alert('XSS')</script>",
                        "POST /comment content=<img src=x onerror=alert('XSS')>",
                        "GET /profile?name=<svg onload=alert('XSS')>"
                    ],
                    'severity': 'medium'
                },
                {
                    'name': '目录遍历攻击',
                    'ip': '198.51.100.75',
                    'requests': [
                        "GET /../../../etc/passwd HTTP/1.1",
                        "GET /..\\..\\..\\windows\\system32\\config\\sam",
                        "GET /admin/../../../database/config.php"
                    ],
                    'severity': 'high'
                }
            ],
            'normal_traffic': [
                {'ip': '192.168.1.100', 'requests': ['GET /', 'GET /about', 'GET /contact']},
                {'ip': '10.0.0.20', 'requests': ['GET /products', 'POST /cart/add', 'GET /checkout']},
                {'ip': '172.16.0.10', 'requests': ['GET /login', 'POST /login', 'GET /dashboard']},
                {'ip': '203.0.113.50', 'requests': ['GET /api/users', 'GET /api/orders', 'POST /api/feedback']}
            ]
        }
    
    def print_header(self, title: str, color: str = Colors.BLUE) -> None:
        """
        打印标题
        
        Args:
            title: 标题文本
            color: 颜色
        """
        print(f"\n{Colors.BOLD}{color}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{color}{title:^60}{Colors.END}")
        print(f"{Colors.BOLD}{color}{'='*60}{Colors.END}\n")
    
    def print_step(self, step: str, status: str = "INFO") -> None:
        """
        打印步骤信息
        
        Args:
            step: 步骤描述
            status: 状态
        """
        color = {
            'INFO': Colors.CYAN,
            'SUCCESS': Colors.GREEN,
            'WARNING': Colors.YELLOW,
            'ERROR': Colors.RED
        }.get(status, Colors.WHITE)
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"{color}[{timestamp}] {step}{Colors.END}")
    
    async def create_demo_config(self) -> None:
        """
        创建演示配置文件
        """
        self.print_step("创建演示配置文件...")
        
        config = create_default_config()
        
        # 启用调试模式
        config['system']['debug'] = True
        config['system']['log_level'] = 'DEBUG'
        
        # 配置演示通知渠道
        config['notification_channels']['console'] = {
            'type': 'webhook',
            'enabled': True,
            'webhook_url': 'http://httpbin.org/post',
            'rate_limit': 10
        }
        
        # 降低监控间隔以便演示
        config['performance_monitoring']['collection_interval'] = 10
        config['intelligent_alerting']['anomaly_detection']['training_interval'] = 300
        
        # 保存配置文件
        import yaml
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        
        self.print_step(f"✓ 演示配置文件已创建: {self.config_path}", "SUCCESS")
    
    async def initialize_system(self) -> None:
        """
        初始化演示系统
        """
        self.print_header("初始化增强版Fail2ban系统", Colors.BLUE)
        
        try:
            # 创建配置文件
            await self.create_demo_config()
            
            # 初始化系统
            self.print_step("初始化系统组件...")
            self.system = EnhancedFail2banSystem(self.config_path, "DEBUG")
            await self.system.initialize()
            
            self.print_step("✓ 系统初始化完成", "SUCCESS")
            
        except Exception as e:
            self.print_step(f"✗ 系统初始化失败: {e}", "ERROR")
            raise
    
    async def demo_multi_tenancy(self) -> None:
        """
        演示多租户功能
        """
        self.print_header("多租户管理演示", Colors.MAGENTA)
        
        if not self.system.tenancy_manager:
            self.print_step("多租户功能未启用，跳过演示", "WARNING")
            return
        
        try:
            # 创建演示租户
            for tenant_data in self.demo_data['tenants']:
                self.print_step(f"创建租户: {tenant_data['name']}")
                
                tenant = await self.system.tenancy_manager.create_tenant(
                    name=tenant_data['name'],
                    description=tenant_data['description'],
                    quota=tenant_data['quota']
                )
                
                if tenant:
                    self.demo_stats['tenants_created'] += 1
                    self.print_step(f"✓ 租户创建成功: {tenant.name} (ID: {tenant.id})", "SUCCESS")
                    
                    # 为每个租户创建用户
                    tenant_users = [user for user in self.demo_data['users'] 
                                  if tenant_data['name'] in ['科技公司A', '电商平台B', '金融机构C']]
                    
                    if tenant_data['name'] == '科技公司A':
                        users_to_create = self.demo_data['users'][:2]
                    elif tenant_data['name'] == '电商平台B':
                        users_to_create = self.demo_data['users'][2:3]
                    else:  # 金融机构C
                        users_to_create = self.demo_data['users'][3:]
                    
                    for user_data in users_to_create:
                        self.print_step(f"  创建用户: {user_data['username']}")
                        
                        user = await self.system.tenancy_manager.create_user(
                            tenant_id=tenant.id,
                            username=user_data['username'],
                            email=user_data['email'],
                            password="demo123",
                            role=user_data['role']
                        )
                        
                        if user:
                            self.demo_stats['users_created'] += 1
                            self.print_step(f"  ✓ 用户创建成功: {user.username}", "SUCCESS")
                
                await asyncio.sleep(0.5)  # 短暂延迟
            
            # 显示租户统计
            tenants = await self.system.tenancy_manager.list_tenants()
            self.print_step(f"\n📊 多租户统计:", "INFO")
            self.print_step(f"  • 总租户数: {len(tenants)}", "INFO")
            self.print_step(f"  • 总用户数: {self.demo_stats['users_created']}", "INFO")
            
        except Exception as e:
            self.print_step(f"✗ 多租户演示失败: {e}", "ERROR")
    
    async def demo_intelligent_alerting(self) -> None:
        """
        演示智能告警功能
        """
        self.print_header("智能告警系统演示", Colors.YELLOW)
        
        if not self.system.alerting_system:
            self.print_step("智能告警功能未启用，跳过演示", "WARNING")
            return
        
        try:
            # 配置动态阈值
            self.print_step("配置动态阈值...")
            await self.system.alerting_system.configure_dynamic_threshold(
                metric="request_rate",
                base_threshold=100,
                adaptation_rate=0.1
            )
            
            # 模拟各种告警事件
            alert_scenarios = [
                {
                    'type': 'threshold_breach',
                    'data': {
                        'timestamp': datetime.now(),
                        'source': 'demo_source',
                        'metric': 'request_rate',
                        'value': 150,
                        'threshold': 100,
                        'ip_address': '192.168.1.100'
                    }
                },
                {
                    'type': 'attack_detected',
                    'data': {
                        'timestamp': datetime.now(),
                        'source': 'ml_detection',
                        'ip_address': '10.0.0.50',
                        'attack_type': 'brute_force',
                        'confidence': 0.95,
                        'severity': 'high'
                    }
                },
                {
                    'type': 'anomaly_detected',
                    'data': {
                        'timestamp': datetime.now(),
                        'source': 'anomaly_detector',
                        'ip_address': '203.0.113.100',
                        'anomaly_score': 0.8,
                        'description': '异常流量模式检测'
                    }
                },
                {
                    'type': 'system_health',
                    'data': {
                        'timestamp': datetime.now(),
                        'source': 'health_monitor',
                        'component': 'database',
                        'status': 'degraded',
                        'details': '数据库响应时间过长'
                    }
                }
            ]
            
            for scenario in alert_scenarios:
                self.print_step(f"触发告警: {scenario['type']}")
                await self.system.alerting_system.process_event(scenario['data'])
                self.demo_stats['alerts_generated'] += 1
                await asyncio.sleep(1)
            
            # 显示告警统计
            alert_stats = await self.system.alerting_system.get_alert_statistics()
            self.print_step(f"\n📊 告警统计:", "INFO")
            self.print_step(f"  • 总告警数: {alert_stats.get('total_alerts', 0)}", "INFO")
            self.print_step(f"  • 高危告警: {alert_stats.get('high_severity', 0)}", "INFO")
            self.print_step(f"  • 中危告警: {alert_stats.get('medium_severity', 0)}", "INFO")
            self.print_step(f"  • 低危告警: {alert_stats.get('low_severity', 0)}", "INFO")
            
        except Exception as e:
            self.print_step(f"✗ 智能告警演示失败: {e}", "ERROR")
    
    async def demo_performance_monitoring(self) -> None:
        """
        演示性能监控功能
        """
        self.print_header("性能监控演示", Colors.GREEN)
        
        if not self.system.performance_monitor:
            self.print_step("性能监控功能未启用，跳过演示", "WARNING")
            return
        
        try:
            # 模拟性能数据收集
            self.print_step("开始性能监控...")
            
            # 收集系统指标
            for i in range(5):
                self.print_step(f"收集性能指标 #{i+1}")
                
                # 模拟一些性能数据
                await self.system.performance_monitor.record_metric(
                    name="cpu_usage",
                    value=random.uniform(20, 80),
                    tags={"host": "demo-server"}
                )
                
                await self.system.performance_monitor.record_metric(
                    name="memory_usage",
                    value=random.uniform(40, 90),
                    tags={"host": "demo-server"}
                )
                
                await self.system.performance_monitor.record_metric(
                    name="response_time",
                    value=random.uniform(50, 500),
                    tags={"endpoint": "/api/users"}
                )
                
                await asyncio.sleep(2)
            
            # 获取性能统计
            stats = await self.system.performance_monitor.get_performance_summary()
            self.print_step(f"\n📊 性能统计:", "INFO")
            self.print_step(f"  • 平均CPU使用率: {stats.get('avg_cpu', 0):.1f}%", "INFO")
            self.print_step(f"  • 平均内存使用率: {stats.get('avg_memory', 0):.1f}%", "INFO")
            self.print_step(f"  • 平均响应时间: {stats.get('avg_response_time', 0):.1f}ms", "INFO")
            
        except Exception as e:
            self.print_step(f"✗ 性能监控演示失败: {e}", "ERROR")
    
    async def demo_security_auditing(self) -> None:
        """
        演示安全审计功能
        """
        self.print_header("安全审计演示", Colors.RED)
        
        if not self.system.security_auditing:
            self.print_step("安全审计功能未启用，跳过演示", "WARNING")
            return
        
        try:
            # 记录各种安全事件
            security_events = [
                {
                    'event_type': SecurityEventType.LOGIN_SUCCESS,
                    'level': SecurityLevel.INFO,
                    'source_ip': '192.168.1.100',
                    'description': '用户成功登录',
                    'metadata': {'username': 'admin', 'user_agent': 'Mozilla/5.0'}
                },
                {
                    'event_type': SecurityEventType.LOGIN_FAILURE,
                    'level': SecurityLevel.WARNING,
                    'source_ip': '10.0.0.50',
                    'description': '用户登录失败',
                    'metadata': {'username': 'admin', 'reason': 'invalid_password'}
                },
                {
                    'event_type': SecurityEventType.ATTACK_DETECTED,
                    'level': SecurityLevel.HIGH,
                    'source_ip': '203.0.113.100',
                    'description': '检测到SQL注入攻击',
                    'metadata': {'attack_type': 'sql_injection', 'payload': "' OR 1=1--"}
                },
                {
                    'event_type': SecurityEventType.IP_BANNED,
                    'level': SecurityLevel.MEDIUM,
                    'source_ip': '172.16.0.25',
                    'description': 'IP地址被封禁',
                    'metadata': {'reason': 'multiple_failed_attempts', 'duration': '1h'}
                },
                {
                    'event_type': SecurityEventType.SUSPICIOUS_ACTIVITY,
                    'level': SecurityLevel.MEDIUM,
                    'source_ip': '198.51.100.75',
                    'description': '检测到可疑活动',
                    'metadata': {'activity': 'directory_traversal', 'path': '/../../../etc/passwd'}
                }
            ]
            
            for event in security_events:
                self.print_step(f"记录安全事件: {event['description']}")
                await self.system.security_auditing.log_security_event(**event)
                await asyncio.sleep(0.5)
            
            # 生成合规报告
            self.print_step("生成合规报告...")
            
            # 获取安全统计
            dashboard_data = await self.system.security_auditing.get_dashboard_data()
            self.print_step(f"\n📊 安全审计统计:", "INFO")
            self.print_step(f"  • 总安全事件: {dashboard_data.get('total_events', 0)}", "INFO")
            self.print_step(f"  • 高危事件: {dashboard_data.get('high_risk_events', 0)}", "INFO")
            self.print_step(f"  • 攻击检测: {dashboard_data.get('attack_detections', 0)}", "INFO")
            self.print_step(f"  • IP封禁: {dashboard_data.get('ip_bans', 0)}", "INFO")
            
        except Exception as e:
            self.print_step(f"✗ 安全审计演示失败: {e}", "ERROR")
    
    async def demo_ml_attack_detection(self) -> None:
        """
        演示机器学习攻击检测功能
        """
        self.print_header("机器学习攻击检测演示", Colors.CYAN)
        
        if not self.system.ml_detection:
            self.print_step("机器学习检测功能未启用，跳过演示", "WARNING")
            return
        
        try:
            # 准备训练数据
            self.print_step("准备训练数据...")
            
            training_data = []
            
            # 正常流量数据
            for traffic in self.demo_data['normal_traffic']:
                for request in traffic['requests']:
                    training_data.append({
                        'ip_address': traffic['ip'],
                        'request': request,
                        'request_count': random.randint(1, 50),
                        'error_rate': random.uniform(0, 0.1),
                        'avg_response_time': random.uniform(50, 200),
                        'unique_paths': random.randint(1, 10),
                        'user_agents': ['Mozilla/5.0', 'Chrome/91.0'],
                        'is_attack': False
                    })
            
            # 攻击流量数据
            for attack in self.demo_data['attack_scenarios']:
                for request in attack['requests'][:10]:  # 限制数量
                    training_data.append({
                        'ip_address': attack['ip'],
                        'request': request,
                        'request_count': random.randint(100, 1000),
                        'error_rate': random.uniform(0.3, 0.9),
                        'avg_response_time': random.uniform(500, 2000),
                        'unique_paths': random.randint(1, 3),
                        'user_agents': ['bot/1.0', 'scanner'],
                        'is_attack': True
                    })
            
            # 训练模型
            self.print_step(f"训练ML模型 (样本数: {len(training_data)})...")
            await self.system.ml_detection.train_models(training_data)
            
            # 测试预测
            self.print_step("\n测试攻击检测...")
            
            test_cases = [
                {
                    'name': '正常用户访问',
                    'data': {
                        'ip_address': '192.168.1.200',
                        'request_count': 25,
                        'error_rate': 0.05,
                        'avg_response_time': 120,
                        'unique_paths': 8,
                        'user_agents': ['Mozilla/5.0']
                    }
                },
                {
                    'name': '可疑大量请求',
                    'data': {
                        'ip_address': 'suspicious.example.com',
                        'request_count': 800,
                        'error_rate': 0.6,
                        'avg_response_time': 1500,
                        'unique_paths': 2,
                        'user_agents': ['bot/1.0']
                    }
                },
                {
                    'name': 'SQL注入尝试',
                    'data': {
                        'ip_address': 'attacker.malicious.com',
                        'request_count': 150,
                        'error_rate': 0.8,
                        'avg_response_time': 2000,
                        'unique_paths': 1,
                        'user_agents': ['sqlmap/1.0']
                    }
                }
            ]
            
            for test_case in test_cases:
                self.print_step(f"测试: {test_case['name']}")
                prediction = await self.system.ml_detection.predict(test_case['data'])
                
                self.demo_stats['ml_predictions'] += 1
                
                status = "SUCCESS" if prediction.is_attack else "INFO"
                self.print_step(
                    f"  结果: {'攻击' if prediction.is_attack else '正常'} "
                    f"(置信度: {prediction.confidence:.2f})",
                    status
                )
                
                await asyncio.sleep(1)
            
            # 获取ML统计
            ml_stats = await self.system.ml_detection.get_model_statistics()
            self.print_step(f"\n📊 ML检测统计:", "INFO")
            self.print_step(f"  • 模型数量: {ml_stats.get('model_count', 0)}", "INFO")
            self.print_step(f"  • 训练样本: {ml_stats.get('training_samples', 0)}", "INFO")
            self.print_step(f"  • 预测次数: {ml_stats.get('predictions', 0)}", "INFO")
            
        except Exception as e:
            self.print_step(f"✗ ML攻击检测演示失败: {e}", "ERROR")
    
    async def demo_notification_system(self) -> None:
        """
        演示通知系统功能
        """
        self.print_header("通知系统演示", Colors.MAGENTA)
        
        if not self.system.datasource_manager:
            self.print_step("通知系统未启用，跳过演示", "WARNING")
            return
        
        try:
            # 发送各种类型的通知
            notifications = [
                {
                    'title': '系统启动通知',
                    'content': '增强版Fail2ban系统已成功启动',
                    'level': 'info',
                    'tags': ['system', 'startup']
                },
                {
                    'title': '安全告警',
                    'content': '检测到来自 203.0.113.100 的DDoS攻击',
                    'level': 'critical',
                    'tags': ['security', 'attack', 'ddos']
                },
                {
                    'title': '性能告警',
                    'content': 'CPU使用率超过阈值 (85%)',
                    'level': 'warning',
                    'tags': ['performance', 'cpu']
                },
                {
                    'title': 'IP封禁通知',
                    'content': 'IP地址 10.0.0.50 因暴力破解攻击被封禁',
                    'level': 'info',
                    'tags': ['security', 'ban']
                }
            ]
            
            for notification in notifications:
                self.print_step(f"发送通知: {notification['title']}")
                
                message = NotificationMessage(
                    title=notification['title'],
                    content=notification['content'],
                    level=notification['level'],
                    timestamp=datetime.now(),
                    source='demo_system',
                    tags=notification['tags'],
                    metadata={'demo': True}
                )
                
                await self.system.datasource_manager.send_notification_to_all_channels(message)
                self.demo_stats['notifications_sent'] += 1
                
                await asyncio.sleep(1)
            
            # 获取通知统计
            notification_stats = await self.system.datasource_manager.get_notification_statistics()
            self.print_step(f"\n📊 通知统计:", "INFO")
            self.print_step(f"  • 总通知数: {notification_stats.get('total_notifications', 0)}", "INFO")
            self.print_step(f"  • 成功发送: {notification_stats.get('successful_notifications', 0)}", "INFO")
            self.print_step(f"  • 发送失败: {notification_stats.get('failed_notifications', 0)}", "INFO")
            
        except Exception as e:
            self.print_step(f"✗ 通知系统演示失败: {e}", "ERROR")
    
    async def demo_attack_simulation(self) -> None:
        """
        演示攻击模拟和检测
        """
        self.print_header("攻击模拟和检测演示", Colors.RED)
        
        try:
            # 模拟各种攻击场景
            for attack in self.demo_data['attack_scenarios']:
                self.print_step(f"模拟攻击: {attack['name']} (来源: {attack['ip']})")
                
                # 处理攻击请求
                for i, request in enumerate(attack['requests'][:5]):  # 限制请求数量
                    log_entry = {
                        'timestamp': datetime.now(),
                        'ip_address': attack['ip'],
                        'request': request,
                        'status_code': 200 if 'GET /' in request else random.choice([400, 401, 403, 500]),
                        'user_agent': 'AttackBot/1.0',
                        'response_time': random.uniform(100, 2000)
                    }
                    
                    # 处理日志条目
                    await self.system._handle_log_entry(log_entry)
                    self.demo_stats['events_processed'] += 1
                    
                    if i % 10 == 0:  # 每10个请求显示一次进度
                        self.print_step(f"  处理请求 {i+1}/{min(len(attack['requests']), 5)}")
                
                # 短暂延迟
                await asyncio.sleep(2)
                
                self.print_step(f"✓ {attack['name']} 模拟完成", "SUCCESS")
            
            self.print_step(f"\n📊 攻击模拟统计:", "INFO")
            self.print_step(f"  • 模拟攻击类型: {len(self.demo_data['attack_scenarios'])}", "INFO")
            self.print_step(f"  • 处理事件数: {self.demo_stats['events_processed']}", "INFO")
            
        except Exception as e:
            self.print_step(f"✗ 攻击模拟失败: {e}", "ERROR")
    
    async def demo_web_interface(self) -> None:
        """
        演示Web管理界面
        """
        self.print_header("Web管理界面演示", Colors.BLUE)
        
        if not self.system.gui_interface:
            self.print_step("Web管理界面未启用，跳过演示", "WARNING")
            return
        
        try:
            # 启动Web服务器
            self.print_step("启动Web管理界面...")
            await self.system.gui_interface.start_server()
            
            # 获取Web界面配置
            web_config = self.system.config.get('web_interface', {})
            host = web_config.get('host', '127.0.0.1')
            port = web_config.get('port', 8080)
            
            self.print_step(f"✓ Web管理界面已启动", "SUCCESS")
            self.print_step(f"  访问地址: http://{host}:{port}", "INFO")
            self.print_step(f"  管理员账户: admin", "INFO")
            self.print_step(f"  管理员密码: admin123", "INFO")
            
            # 显示可用的API端点
            self.print_step(f"\n🌐 可用的API端点:", "INFO")
            endpoints = [
                f"http://{host}:{port}/",
                f"http://{host}:{port}/api/tenants",
                f"http://{host}:{port}/api/users",
                f"http://{host}:{port}/api/alerts",
                f"http://{host}:{port}/api/monitoring/metrics",
                f"http://{host}:{port}/api/security/events",
                f"http://{host}:{port}/health"
            ]
            
            for endpoint in endpoints:
                self.print_step(f"  • {endpoint}", "INFO")
            
        except Exception as e:
            self.print_step(f"✗ Web界面演示失败: {e}", "ERROR")
    
    async def print_demo_summary(self) -> None:
        """
        打印演示总结
        """
        self.print_header("演示总结", Colors.GREEN)
        
        # 系统状态
        system_status = self.system.get_system_status()
        
        print(f"{Colors.BOLD}🎉 增强版Fail2ban系统演示完成!{Colors.END}\n")
        
        print(f"{Colors.BOLD}📊 演示统计:{Colors.END}")
        print(f"  • 创建租户: {self.demo_stats['tenants_created']}")
        print(f"  • 创建用户: {self.demo_stats['users_created']}")
        print(f"  • 生成告警: {self.demo_stats['alerts_generated']}")
        print(f"  • 处理事件: {self.demo_stats['events_processed']}")
        print(f"  • ML预测: {self.demo_stats['ml_predictions']}")
        print(f"  • 发送通知: {self.demo_stats['notifications_sent']}")
        
        print(f"\n{Colors.BOLD}🛡️ 系统状态:{Colors.END}")
        print(f"  • 运行状态: {'✓ 运行中' if system_status['is_running'] else '✗ 已停止'}")
        print(f"  • 运行时间: {system_status['uptime_seconds']}秒")
        print(f"  • 启用功能: {len(system_status['enabled_features'])}个")
        
        print(f"\n{Colors.BOLD}🌟 主要功能:{Colors.END}")
        for feature in system_status['enabled_features']:
            print(f"  ✓ {feature}")
        
        if self.system.gui_interface:
            web_config = self.system.config.get('web_interface', {})
            host = web_config.get('host', '127.0.0.1')
            port = web_config.get('port', 8080)
            
            print(f"\n{Colors.BOLD}🌐 Web管理界面:{Colors.END}")
            print(f"  • 访问地址: {Colors.CYAN}http://{host}:{port}{Colors.END}")
            print(f"  • 管理员账户: admin")
            print(f"  • 管理员密码: admin123")
        
        print(f"\n{Colors.BOLD}📚 下一步:{Colors.END}")
        print(f"  1. 访问Web管理界面查看详细信息")
        print(f"  2. 配置真实的日志文件路径")
        print(f"  3. 设置邮件和其他通知渠道")
        print(f"  4. 根据业务需求调整检测规则")
        print(f"  5. 使用真实数据训练ML模型")
        
        print(f"\n{Colors.CYAN}演示配置文件: {self.config_path}{Colors.END}")
        print(f"{Colors.CYAN}完整文档: README.md{Colors.END}")
        print(f"{Colors.CYAN}快速指南: QUICKSTART.md{Colors.END}")
    
    async def run_full_demo(self, interactive: bool = True) -> None:
        """
        运行完整演示
        
        Args:
            interactive: 是否交互式运行
        """
        try:
            # 初始化系统
            await self.initialize_system()
            
            # 演示各个功能模块
            demo_modules = [
                ("多租户管理", self.demo_multi_tenancy),
                ("智能告警系统", self.demo_intelligent_alerting),
                ("性能监控", self.demo_performance_monitoring),
                ("安全审计", self.demo_security_auditing),
                ("机器学习检测", self.demo_ml_attack_detection),
                ("通知系统", self.demo_notification_system),
                ("攻击模拟", self.demo_attack_simulation),
                ("Web管理界面", self.demo_web_interface)
            ]
            
            for module_name, demo_func in demo_modules:
                if interactive:
                    input(f"\n按回车键继续演示: {module_name}...")
                
                await demo_func()
                
                if interactive:
                    await asyncio.sleep(2)
            
            # 打印演示总结
            await self.print_demo_summary()
            
            if interactive:
                input("\n按回车键结束演示...")
            
        except KeyboardInterrupt:
            self.print_step("\n演示被用户中断", "WARNING")
        except Exception as e:
            self.print_step(f"\n演示过程中发生错误: {e}", "ERROR")
        finally:
            # 清理资源
            if self.system:
                await self.system.stop()
    
    async def run_quick_demo(self) -> None:
        """
        运行快速演示（非交互式）
        """
        self.print_header("快速演示模式", Colors.CYAN)
        await self.run_full_demo(interactive=False)


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(
        description="增强版分布式Fail2ban系统演示",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  %(prog)s                           # 运行完整交互式演示
  %(prog)s --quick                   # 运行快速演示
  %(prog)s --config demo.yaml       # 使用自定义配置文件
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='demo_config.yaml',
        help='演示配置文件路径 (默认: demo_config.yaml)'
    )
    
    parser.add_argument(
        '--quick', '-q',
        action='store_true',
        help='快速演示模式（非交互式）'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='增强版Fail2ban系统演示 v2.0.0'
    )
    
    args = parser.parse_args()
    
    # 创建演示实例
    demo = EnhancedFail2banDemo(args.config)
    
    try:
        print(f"{Colors.BOLD}{Colors.BLUE}🛡️  增强版分布式Fail2ban系统演示{Colors.END}")
        print(f"{Colors.CYAN}版本: 2.0.0{Colors.END}")
        print(f"{Colors.CYAN}配置文件: {args.config}{Colors.END}")
        
        if args.quick:
            print(f"{Colors.YELLOW}运行模式: 快速演示{Colors.END}\n")
            asyncio.run(demo.run_quick_demo())
        else:
            print(f"{Colors.YELLOW}运行模式: 完整交互式演示{Colors.END}")
            print(f"{Colors.YELLOW}提示: 按 Ctrl+C 可随时退出演示{Colors.END}\n")
            
            input("按回车键开始演示...")
            asyncio.run(demo.run_full_demo())
        
        print(f"\n{Colors.GREEN}✅ 演示完成!{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}演示已取消{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}演示过程中发生错误: {e}{Colors.END}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()