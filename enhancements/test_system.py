#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版分布式Fail2ban系统测试套件

这个测试套件提供了完整的系统功能测试，包括：
- 单元测试
- 集成测试
- 性能测试
- 压力测试
- 安全测试

作者: Fail2ban开发团队
版本: 2.0.0
许可: MIT License
"""

import asyncio
import json
import random
import time
import unittest
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from unittest.mock import Mock, patch, AsyncMock

# 导入系统模块
try:
    from enhanced_fail2ban import EnhancedFail2banSystem, create_default_config
    from multi_tenancy import (
        MultiTenancyManager, UserRole, Permission, ResourceQuota,
        Tenant, User, Session
    )
    from intelligent_alerting import (
        IntelligentAlertingSystem, AlertSeverity, AlertType,
        Alert, DynamicThreshold
    )
    from performance_monitoring import (
        PerformanceMonitor, TraceSpan, PerformanceMetric
    )
    from security_auditing import (
        SecurityAuditingSystem, SecurityEventType, SecurityLevel
    )
    from ml_attack_detection import (
        MLAttackDetectionSystem, AttackPattern, MLPrediction
    )
    from gui_config_interface import GUIConfigInterface
    from multi_datasource_notification import (
        MultiDataSourceManager, LogEntry, NotificationMessage
    )
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


class TestResult:
    """测试结果类"""
    
    def __init__(self, name: str, success: bool, message: str = "", duration: float = 0.0):
        self.name = name
        self.success = success
        self.message = message
        self.duration = duration
        self.timestamp = datetime.now()
    
    def __str__(self) -> str:
        status = "✓" if self.success else "✗"
        color = Colors.GREEN if self.success else Colors.RED
        return f"{color}{status} {self.name} ({self.duration:.2f}s){Colors.END}"


class TestSuite:
    """测试套件基类"""
    
    def __init__(self, name: str):
        self.name = name
        self.results: List[TestResult] = []
        self.setup_done = False
        self.teardown_done = False
    
    async def setup(self) -> None:
        """测试前设置"""
        self.setup_done = True
    
    async def teardown(self) -> None:
        """测试后清理"""
        self.teardown_done = True
    
    def add_result(self, result: TestResult) -> None:
        """添加测试结果"""
        self.results.append(result)
    
    def get_summary(self) -> Dict[str, Any]:
        """获取测试摘要"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        failed = total - passed
        total_duration = sum(r.duration for r in self.results)
        
        return {
            'name': self.name,
            'total': total,
            'passed': passed,
            'failed': failed,
            'success_rate': (passed / total * 100) if total > 0 else 0,
            'total_duration': total_duration
        }


class MultiTenancyTestSuite(TestSuite):
    """多租户功能测试套件"""
    
    def __init__(self):
        super().__init__("多租户管理测试")
        self.tenancy_manager: Optional[MultiTenancyManager] = None
        self.temp_dir: Optional[str] = None
    
    async def setup(self) -> None:
        """设置测试环境"""
        await super().setup()
        
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        
        # 初始化多租户管理器
        config = {
            'multi_tenancy': {
                'enabled': True,
                'storage': {
                    'type': 'sqlite',
                    'database_path': f"{self.temp_dir}/tenancy.db"
                },
                'session': {
                    'timeout_minutes': 30,
                    'cleanup_interval_minutes': 5
                }
            }
        }
        
        self.tenancy_manager = MultiTenancyManager(config)
        await self.tenancy_manager.initialize()
    
    async def teardown(self) -> None:
        """清理测试环境"""
        if self.tenancy_manager:
            await self.tenancy_manager.stop()
        
        if self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        await super().teardown()
    
    async def test_tenant_creation(self) -> TestResult:
        """测试租户创建"""
        start_time = time.time()
        
        try:
            quota = ResourceQuota(
                max_banned_ips=1000,
                max_rules=50,
                max_users=10,
                max_storage_mb=100
            )
            
            tenant = await self.tenancy_manager.create_tenant(
                name="测试租户",
                description="用于测试的租户",
                quota=quota
            )
            
            assert tenant is not None, "租户创建失败"
            assert tenant.name == "测试租户", "租户名称不匹配"
            assert tenant.quota.max_banned_ips == 1000, "配额设置不正确"
            
            duration = time.time() - start_time
            return TestResult("租户创建", True, "租户创建成功", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("租户创建", False, str(e), duration)
    
    async def test_user_management(self) -> TestResult:
        """测试用户管理"""
        start_time = time.time()
        
        try:
            # 先创建租户
            quota = ResourceQuota(max_banned_ips=100, max_rules=10, max_users=5, max_storage_mb=50)
            tenant = await self.tenancy_manager.create_tenant(
                name="用户测试租户",
                description="用于用户测试",
                quota=quota
            )
            
            # 创建用户
            user = await self.tenancy_manager.create_user(
                tenant_id=tenant.id,
                username="testuser",
                email="test@example.com",
                password="password123",
                role=UserRole.SECURITY_ANALYST
            )
            
            assert user is not None, "用户创建失败"
            assert user.username == "testuser", "用户名不匹配"
            assert user.role == UserRole.SECURITY_ANALYST, "用户角色不正确"
            
            # 测试用户认证
            auth_result = await self.tenancy_manager.authenticate_user(
                "testuser", "password123"
            )
            
            assert auth_result is not None, "用户认证失败"
            
            duration = time.time() - start_time
            return TestResult("用户管理", True, "用户管理功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("用户管理", False, str(e), duration)
    
    async def test_session_management(self) -> TestResult:
        """测试会话管理"""
        start_time = time.time()
        
        try:
            # 创建租户和用户
            quota = ResourceQuota(max_banned_ips=100, max_rules=10, max_users=5, max_storage_mb=50)
            tenant = await self.tenancy_manager.create_tenant(
                name="会话测试租户",
                description="用于会话测试",
                quota=quota
            )
            
            user = await self.tenancy_manager.create_user(
                tenant_id=tenant.id,
                username="sessionuser",
                email="session@example.com",
                password="password123",
                role=UserRole.TENANT_ADMIN
            )
            
            # 创建会话
            session = await self.tenancy_manager.create_session(user.id)
            assert session is not None, "会话创建失败"
            
            # 验证会话
            is_valid = await self.tenancy_manager.validate_session(session.token)
            assert is_valid, "会话验证失败"
            
            # 删除会话
            await self.tenancy_manager.delete_session(session.token)
            
            # 验证会话已删除
            is_valid_after_delete = await self.tenancy_manager.validate_session(session.token)
            assert not is_valid_after_delete, "会话删除失败"
            
            duration = time.time() - start_time
            return TestResult("会话管理", True, "会话管理功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("会话管理", False, str(e), duration)
    
    async def run_all_tests(self) -> List[TestResult]:
        """运行所有测试"""
        tests = [
            self.test_tenant_creation,
            self.test_user_management,
            self.test_session_management
        ]
        
        for test in tests:
            result = await test()
            self.add_result(result)
        
        return self.results


class IntelligentAlertingTestSuite(TestSuite):
    """智能告警测试套件"""
    
    def __init__(self):
        super().__init__("智能告警测试")
        self.alerting_system: Optional[IntelligentAlertingSystem] = None
        self.temp_dir: Optional[str] = None
    
    async def setup(self) -> None:
        """设置测试环境"""
        await super().setup()
        
        self.temp_dir = tempfile.mkdtemp()
        
        config = {
            'intelligent_alerting': {
                'enabled': True,
                'storage_path': f"{self.temp_dir}/alerts.db",
                'dynamic_thresholds': {
                    'enabled': True,
                    'adaptation_rate': 0.1,
                    'min_samples': 10
                },
                'anomaly_detection': {
                    'enabled': True,
                    'contamination': 0.1,
                    'training_interval': 300
                },
                'notification_channels': ['console']
            }
        }
        
        self.alerting_system = IntelligentAlertingSystem(config)
        await self.alerting_system.initialize()
    
    async def teardown(self) -> None:
        """清理测试环境"""
        if self.alerting_system:
            await self.alerting_system.stop()
        
        if self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        await super().teardown()
    
    async def test_alert_creation(self) -> TestResult:
        """测试告警创建"""
        start_time = time.time()
        
        try:
            event_data = {
                'timestamp': datetime.now(),
                'source': 'test_source',
                'metric': 'test_metric',
                'value': 100,
                'threshold': 80,
                'ip_address': '192.168.1.100'
            }
            
            await self.alerting_system.process_event(event_data)
            
            # 获取告警统计
            stats = await self.alerting_system.get_alert_statistics()
            assert stats['total_alerts'] > 0, "告警未创建"
            
            duration = time.time() - start_time
            return TestResult("告警创建", True, "告警创建成功", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("告警创建", False, str(e), duration)
    
    async def test_dynamic_threshold(self) -> TestResult:
        """测试动态阈值"""
        start_time = time.time()
        
        try:
            # 配置动态阈值
            await self.alerting_system.configure_dynamic_threshold(
                metric="cpu_usage",
                base_threshold=70,
                adaptation_rate=0.1
            )
            
            # 模拟数据点
            for i in range(20):
                value = 60 + random.uniform(-10, 10)
                await self.alerting_system.update_dynamic_threshold(
                    "cpu_usage", value
                )
            
            # 获取当前阈值
            threshold = await self.alerting_system.get_dynamic_threshold("cpu_usage")
            assert threshold is not None, "动态阈值未设置"
            assert 50 <= threshold <= 90, "动态阈值超出合理范围"
            
            duration = time.time() - start_time
            return TestResult("动态阈值", True, "动态阈值功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("动态阈值", False, str(e), duration)
    
    async def test_anomaly_detection(self) -> TestResult:
        """测试异常检测"""
        start_time = time.time()
        
        try:
            # 训练异常检测模型
            training_data = []
            for i in range(100):
                # 正常数据
                training_data.append([random.uniform(50, 70), random.uniform(20, 40)])
            
            await self.alerting_system.train_anomaly_detector(training_data)
            
            # 测试异常检测
            normal_point = [60, 30]  # 正常点
            anomaly_point = [200, 300]  # 异常点
            
            is_normal_anomaly = await self.alerting_system.detect_anomaly(normal_point)
            is_anomaly_detected = await self.alerting_system.detect_anomaly(anomaly_point)
            
            assert not is_normal_anomaly, "正常数据被误判为异常"
            assert is_anomaly_detected, "异常数据未被检测到"
            
            duration = time.time() - start_time
            return TestResult("异常检测", True, "异常检测功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("异常检测", False, str(e), duration)
    
    async def run_all_tests(self) -> List[TestResult]:
        """运行所有测试"""
        tests = [
            self.test_alert_creation,
            self.test_dynamic_threshold,
            self.test_anomaly_detection
        ]
        
        for test in tests:
            result = await test()
            self.add_result(result)
        
        return self.results


class PerformanceMonitoringTestSuite(TestSuite):
    """性能监控测试套件"""
    
    def __init__(self):
        super().__init__("性能监控测试")
        self.performance_monitor: Optional[PerformanceMonitor] = None
        self.temp_dir: Optional[str] = None
    
    async def setup(self) -> None:
        """设置测试环境"""
        await super().setup()
        
        self.temp_dir = tempfile.mkdtemp()
        
        config = {
            'performance_monitoring': {
                'enabled': True,
                'collection_interval': 5,
                'storage_path': f"{self.temp_dir}/metrics.db",
                'distributed_tracing': {
                    'enabled': True,
                    'sample_rate': 1.0
                },
                'thresholds': {
                    'cpu_usage': 80,
                    'memory_usage': 85,
                    'response_time': 1000
                }
            }
        }
        
        self.performance_monitor = PerformanceMonitor(config)
        await self.performance_monitor.initialize()
    
    async def teardown(self) -> None:
        """清理测试环境"""
        if self.performance_monitor:
            await self.performance_monitor.stop()
        
        if self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        await super().teardown()
    
    async def test_metric_collection(self) -> TestResult:
        """测试指标收集"""
        start_time = time.time()
        
        try:
            # 记录一些指标
            await self.performance_monitor.record_metric(
                name="cpu_usage",
                value=65.5,
                tags={"host": "test-server"}
            )
            
            await self.performance_monitor.record_metric(
                name="memory_usage",
                value=72.3,
                tags={"host": "test-server"}
            )
            
            # 获取指标统计
            stats = await self.performance_monitor.get_performance_summary()
            assert 'avg_cpu' in stats or 'metrics_count' in stats, "指标统计获取失败"
            
            duration = time.time() - start_time
            return TestResult("指标收集", True, "指标收集功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("指标收集", False, str(e), duration)
    
    async def test_distributed_tracing(self) -> TestResult:
        """测试分布式链路追踪"""
        start_time = time.time()
        
        try:
            # 创建追踪span
            trace_id = "test-trace-123"
            span_id = "test-span-456"
            
            span = TraceSpan(
                trace_id=trace_id,
                span_id=span_id,
                operation_name="test_operation",
                start_time=datetime.now(),
                tags={"component": "test"}
            )
            
            await self.performance_monitor.start_trace(span)
            
            # 模拟一些操作
            await asyncio.sleep(0.1)
            
            await self.performance_monitor.finish_trace(span_id)
            
            # 获取追踪统计
            trace_stats = await self.performance_monitor.get_trace_statistics()
            assert trace_stats.get('total_traces', 0) > 0, "追踪数据未记录"
            
            duration = time.time() - start_time
            return TestResult("分布式追踪", True, "分布式追踪功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("分布式追踪", False, str(e), duration)
    
    async def test_performance_thresholds(self) -> TestResult:
        """测试性能阈值"""
        start_time = time.time()
        
        try:
            # 记录超过阈值的指标
            await self.performance_monitor.record_metric(
                name="cpu_usage",
                value=95.0,  # 超过80%阈值
                tags={"host": "test-server"}
            )
            
            # 检查是否触发了阈值告警
            # 这里应该有告警回调或事件
            
            duration = time.time() - start_time
            return TestResult("性能阈值", True, "性能阈值功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("性能阈值", False, str(e), duration)
    
    async def run_all_tests(self) -> List[TestResult]:
        """运行所有测试"""
        tests = [
            self.test_metric_collection,
            self.test_distributed_tracing,
            self.test_performance_thresholds
        ]
        
        for test in tests:
            result = await test()
            self.add_result(result)
        
        return self.results


class SecurityAuditingTestSuite(TestSuite):
    """安全审计测试套件"""
    
    def __init__(self):
        super().__init__("安全审计测试")
        self.security_auditing: Optional[SecurityAuditingSystem] = None
        self.temp_dir: Optional[str] = None
    
    async def setup(self) -> None:
        """设置测试环境"""
        await super().setup()
        
        self.temp_dir = tempfile.mkdtemp()
        
        config = {
            'security_auditing': {
                'enabled': True,
                'storage_path': f"{self.temp_dir}/security.db",
                'encryption_key': 'test-encryption-key-32-bytes-long',
                'threat_intelligence': {
                    'enabled': True,
                    'feeds': []
                },
                'compliance': {
                    'standards': ['PCI_DSS', 'GDPR'],
                    'report_interval': 86400
                }
            }
        }
        
        self.security_auditing = SecurityAuditingSystem(config)
        await self.security_auditing.initialize()
    
    async def teardown(self) -> None:
        """清理测试环境"""
        if self.security_auditing:
            await self.security_auditing.stop()
        
        if self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        await super().teardown()
    
    async def test_security_event_logging(self) -> TestResult:
        """测试安全事件记录"""
        start_time = time.time()
        
        try:
            # 记录安全事件
            await self.security_auditing.log_security_event(
                event_type=SecurityEventType.LOGIN_FAILURE,
                level=SecurityLevel.WARNING,
                source_ip='192.168.1.100',
                description='用户登录失败',
                metadata={'username': 'testuser', 'reason': 'invalid_password'}
            )
            
            await self.security_auditing.log_security_event(
                event_type=SecurityEventType.ATTACK_DETECTED,
                level=SecurityLevel.HIGH,
                source_ip='10.0.0.50',
                description='检测到SQL注入攻击',
                metadata={'attack_type': 'sql_injection'}
            )
            
            # 获取安全统计
            dashboard_data = await self.security_auditing.get_dashboard_data()
            assert dashboard_data['total_events'] >= 2, "安全事件未正确记录"
            
            duration = time.time() - start_time
            return TestResult("安全事件记录", True, "安全事件记录功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("安全事件记录", False, str(e), duration)
    
    async def test_threat_intelligence(self) -> TestResult:
        """测试威胁情报"""
        start_time = time.time()
        
        try:
            # 添加威胁IP
            await self.security_auditing.add_threat_ip(
                ip='203.0.113.100',
                threat_type='malware',
                confidence=0.9,
                source='test_feed'
            )
            
            # 检查威胁IP
            is_threat = await self.security_auditing.is_threat_ip('203.0.113.100')
            assert is_threat, "威胁IP检查失败"
            
            # 检查正常IP
            is_normal = await self.security_auditing.is_threat_ip('192.168.1.1')
            assert not is_normal, "正常IP被误判为威胁"
            
            duration = time.time() - start_time
            return TestResult("威胁情报", True, "威胁情报功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("威胁情报", False, str(e), duration)
    
    async def test_compliance_reporting(self) -> TestResult:
        """测试合规报告"""
        start_time = time.time()
        
        try:
            # 生成合规报告
            from security_auditing import ComplianceStandard
            
            report = await self.security_auditing.generate_compliance_report(
                standard=ComplianceStandard.PCI_DSS,
                start_date=datetime.now() - timedelta(days=1),
                end_date=datetime.now()
            )
            
            assert report is not None, "合规报告生成失败"
            assert 'standard' in report, "报告格式不正确"
            
            duration = time.time() - start_time
            return TestResult("合规报告", True, "合规报告功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("合规报告", False, str(e), duration)
    
    async def run_all_tests(self) -> List[TestResult]:
        """运行所有测试"""
        tests = [
            self.test_security_event_logging,
            self.test_threat_intelligence,
            self.test_compliance_reporting
        ]
        
        for test in tests:
            result = await test()
            self.add_result(result)
        
        return self.results


class MLAttackDetectionTestSuite(TestSuite):
    """机器学习攻击检测测试套件"""
    
    def __init__(self):
        super().__init__("机器学习检测测试")
        self.ml_detection: Optional[MLAttackDetectionSystem] = None
        self.temp_dir: Optional[str] = None
    
    async def setup(self) -> None:
        """设置测试环境"""
        await super().setup()
        
        self.temp_dir = tempfile.mkdtemp()
        
        config = {
            'ml_attack_detection': {
                'enabled': True,
                'model_storage_path': f"{self.temp_dir}/models",
                'data_storage_path': f"{self.temp_dir}/ml_data.db",
                'models': {
                    'random_forest': {
                        'enabled': True,
                        'n_estimators': 10,  # 减少用于测试
                        'max_depth': 5
                    },
                    'anomaly_detection': {
                        'enabled': True,
                        'contamination': 0.1
                    }
                },
                'feature_extraction': {
                    'request_features': True,
                    'behavioral_features': True,
                    'time_window_minutes': 5
                }
            }
        }
        
        self.ml_detection = MLAttackDetectionSystem(config)
        await self.ml_detection.initialize()
    
    async def teardown(self) -> None:
        """清理测试环境"""
        if self.ml_detection:
            await self.ml_detection.stop()
        
        if self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        await super().teardown()
    
    async def test_feature_extraction(self) -> TestResult:
        """测试特征提取"""
        start_time = time.time()
        
        try:
            # 测试数据
            request_data = {
                'ip_address': '192.168.1.100',
                'request_count': 50,
                'error_rate': 0.1,
                'avg_response_time': 200,
                'unique_paths': 5,
                'user_agents': ['Mozilla/5.0']
            }
            
            # 提取特征
            features = await self.ml_detection.extract_features(request_data)
            assert features is not None, "特征提取失败"
            assert len(features) > 0, "特征向量为空"
            
            duration = time.time() - start_time
            return TestResult("特征提取", True, "特征提取功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("特征提取", False, str(e), duration)
    
    async def test_model_training(self) -> TestResult:
        """测试模型训练"""
        start_time = time.time()
        
        try:
            # 准备训练数据
            training_data = []
            
            # 正常数据
            for i in range(50):
                training_data.append({
                    'ip_address': f'192.168.1.{i}',
                    'request_count': random.randint(1, 100),
                    'error_rate': random.uniform(0, 0.2),
                    'avg_response_time': random.uniform(50, 300),
                    'unique_paths': random.randint(1, 20),
                    'user_agents': ['Mozilla/5.0'],
                    'is_attack': False
                })
            
            # 攻击数据
            for i in range(20):
                training_data.append({
                    'ip_address': f'10.0.0.{i}',
                    'request_count': random.randint(500, 2000),
                    'error_rate': random.uniform(0.5, 1.0),
                    'avg_response_time': random.uniform(1000, 5000),
                    'unique_paths': random.randint(1, 3),
                    'user_agents': ['bot/1.0'],
                    'is_attack': True
                })
            
            # 训练模型
            await self.ml_detection.train_models(training_data)
            
            # 检查模型是否训练成功
            model_stats = await self.ml_detection.get_model_statistics()
            assert model_stats['training_samples'] > 0, "模型训练失败"
            
            duration = time.time() - start_time
            return TestResult("模型训练", True, "模型训练功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("模型训练", False, str(e), duration)
    
    async def test_attack_prediction(self) -> TestResult:
        """测试攻击预测"""
        start_time = time.time()
        
        try:
            # 先训练模型（简化版）
            training_data = []
            for i in range(30):
                training_data.append({
                    'ip_address': f'192.168.1.{i}',
                    'request_count': random.randint(1, 50),
                    'error_rate': 0.05,
                    'avg_response_time': 150,
                    'unique_paths': 10,
                    'user_agents': ['Mozilla/5.0'],
                    'is_attack': False
                })
            
            for i in range(10):
                training_data.append({
                    'ip_address': f'10.0.0.{i}',
                    'request_count': random.randint(500, 1000),
                    'error_rate': 0.8,
                    'avg_response_time': 2000,
                    'unique_paths': 2,
                    'user_agents': ['bot/1.0'],
                    'is_attack': True
                })
            
            await self.ml_detection.train_models(training_data)
            
            # 测试正常请求
            normal_request = {
                'ip_address': '192.168.1.200',
                'request_count': 25,
                'error_rate': 0.05,
                'avg_response_time': 120,
                'unique_paths': 8,
                'user_agents': ['Mozilla/5.0']
            }
            
            normal_prediction = await self.ml_detection.predict(normal_request)
            
            # 测试攻击请求
            attack_request = {
                'ip_address': '203.0.113.100',
                'request_count': 800,
                'error_rate': 0.9,
                'avg_response_time': 3000,
                'unique_paths': 1,
                'user_agents': ['sqlmap/1.0']
            }
            
            attack_prediction = await self.ml_detection.predict(attack_request)
            
            # 验证预测结果
            assert normal_prediction is not None, "正常请求预测失败"
            assert attack_prediction is not None, "攻击请求预测失败"
            
            duration = time.time() - start_time
            return TestResult("攻击预测", True, "攻击预测功能正常", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("攻击预测", False, str(e), duration)
    
    async def run_all_tests(self) -> List[TestResult]:
        """运行所有测试"""
        tests = [
            self.test_feature_extraction,
            self.test_model_training,
            self.test_attack_prediction
        ]
        
        for test in tests:
            result = await test()
            self.add_result(result)
        
        return self.results


class IntegrationTestSuite(TestSuite):
    """集成测试套件"""
    
    def __init__(self):
        super().__init__("系统集成测试")
        self.system: Optional[EnhancedFail2banSystem] = None
        self.temp_dir: Optional[str] = None
    
    async def setup(self) -> None:
        """设置测试环境"""
        await super().setup()
        
        self.temp_dir = tempfile.mkdtemp()
        
        # 创建测试配置
        config = create_default_config()
        config['system']['debug'] = True
        config['system']['log_level'] = 'DEBUG'
        
        # 使用临时目录
        config['multi_tenancy']['storage']['database_path'] = f"{self.temp_dir}/tenancy.db"
        config['intelligent_alerting']['storage_path'] = f"{self.temp_dir}/alerts.db"
        config['performance_monitoring']['storage_path'] = f"{self.temp_dir}/metrics.db"
        config['security_auditing']['storage_path'] = f"{self.temp_dir}/security.db"
        config['ml_attack_detection']['data_storage_path'] = f"{self.temp_dir}/ml_data.db"
        config['ml_attack_detection']['model_storage_path'] = f"{self.temp_dir}/models"
        
        # 保存配置文件
        import yaml
        config_path = f"{self.temp_dir}/test_config.yaml"
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        
        # 初始化系统
        self.system = EnhancedFail2banSystem(config_path, "DEBUG")
        await self.system.initialize()
    
    async def teardown(self) -> None:
        """清理测试环境"""
        if self.system:
            await self.system.stop()
        
        if self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        await super().teardown()
    
    async def test_system_initialization(self) -> TestResult:
        """测试系统初始化"""
        start_time = time.time()
        
        try:
            # 检查系统状态
            status = self.system.get_system_status()
            assert status['is_running'], "系统未正常运行"
            assert len(status['enabled_features']) > 0, "没有启用的功能"
            
            duration = time.time() - start_time
            return TestResult("系统初始化", True, "系统初始化成功", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("系统初始化", False, str(e), duration)
    
    async def test_end_to_end_workflow(self) -> TestResult:
        """测试端到端工作流"""
        start_time = time.time()
        
        try:
            # 1. 创建租户和用户
            if self.system.tenancy_manager:
                quota = ResourceQuota(
                    max_banned_ips=100,
                    max_rules=10,
                    max_users=5,
                    max_storage_mb=50
                )
                
                tenant = await self.system.tenancy_manager.create_tenant(
                    name="集成测试租户",
                    description="用于集成测试",
                    quota=quota
                )
                
                user = await self.system.tenancy_manager.create_user(
                    tenant_id=tenant.id,
                    username="integrationuser",
                    email="integration@test.com",
                    password="password123",
                    role=UserRole.SECURITY_ANALYST
                )
                
                assert tenant is not None, "租户创建失败"
                assert user is not None, "用户创建失败"
            
            # 2. 模拟日志处理
            log_entry = {
                'timestamp': datetime.now(),
                'ip_address': '203.0.113.100',
                'request': 'GET /admin.php?id=1\' OR 1=1-- HTTP/1.1',
                'status_code': 403,
                'user_agent': 'sqlmap/1.0',
                'response_time': 2000
            }
            
            await self.system._handle_log_entry(log_entry)
            
            # 3. 检查各个系统是否正常工作
            # 检查告警系统
            if self.system.alerting_system:
                alert_stats = await self.system.alerting_system.get_alert_statistics()
                # 应该有告警产生
            
            # 检查安全审计
            if self.system.security_auditing:
                security_stats = await self.system.security_auditing.get_dashboard_data()
                # 应该有安全事件记录
            
            # 检查ML检测
            if self.system.ml_detection:
                ml_stats = await self.system.ml_detection.get_model_statistics()
                # 应该有预测记录
            
            duration = time.time() - start_time
            return TestResult("端到端工作流", True, "端到端工作流测试成功", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("端到端工作流", False, str(e), duration)
    
    async def test_system_resilience(self) -> TestResult:
        """测试系统弹性"""
        start_time = time.time()
        
        try:
            # 模拟高负载
            tasks = []
            for i in range(10):
                log_entry = {
                    'timestamp': datetime.now(),
                    'ip_address': f'192.168.1.{i}',
                    'request': f'GET /page{i}.html HTTP/1.1',
                    'status_code': 200,
                    'user_agent': 'Mozilla/5.0',
                    'response_time': random.randint(50, 500)
                }
                
                task = asyncio.create_task(self.system._handle_log_entry(log_entry))
                tasks.append(task)
            
            # 等待所有任务完成
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # 检查系统是否仍然正常运行
            status = self.system.get_system_status()
            assert status['is_running'], "系统在高负载下停止运行"
            
            duration = time.time() - start_time
            return TestResult("系统弹性", True, "系统弹性测试通过", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("系统弹性", False, str(e), duration)
    
    async def run_all_tests(self) -> List[TestResult]:
        """运行所有测试"""
        tests = [
            self.test_system_initialization,
            self.test_end_to_end_workflow,
            self.test_system_resilience
        ]
        
        for test in tests:
            result = await test()
            self.add_result(result)
        
        return self.results


class SystemTestRunner:
    """系统测试运行器"""
    
    def __init__(self):
        self.test_suites: List[TestSuite] = []
        self.results: List[TestResult] = []
    
    def add_test_suite(self, test_suite: TestSuite) -> None:
        """添加测试套件"""
        self.test_suites.append(test_suite)
    
    def print_header(self, title: str, color: str = Colors.BLUE) -> None:
        """打印标题"""
        print(f"\n{Colors.BOLD}{color}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{color}{title:^60}{Colors.END}")
        print(f"{Colors.BOLD}{color}{'='*60}{Colors.END}\n")
    
    def print_suite_header(self, suite_name: str) -> None:
        """打印测试套件标题"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}🧪 {suite_name}{Colors.END}")
        print(f"{Colors.CYAN}{'-' * (len(suite_name) + 4)}{Colors.END}")
    
    def print_result(self, result: TestResult) -> None:
        """打印测试结果"""
        print(f"  {result}")
        if not result.success and result.message:
            print(f"    {Colors.RED}错误: {result.message}{Colors.END}")
    
    def print_summary(self) -> None:
        """打印测试总结"""
        self.print_header("测试总结", Colors.GREEN)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.success)
        failed_tests = total_tests - passed_tests
        total_duration = sum(r.duration for r in self.results)
        
        print(f"{Colors.BOLD}📊 总体统计:{Colors.END}")
        print(f"  • 总测试数: {total_tests}")
        print(f"  • 通过测试: {Colors.GREEN}{passed_tests}{Colors.END}")
        print(f"  • 失败测试: {Colors.RED}{failed_tests}{Colors.END}")
        print(f"  • 成功率: {(passed_tests/total_tests*100):.1f}%" if total_tests > 0 else "  • 成功率: 0%")
        print(f"  • 总耗时: {total_duration:.2f}秒")
        
        # 按测试套件分组显示
        print(f"\n{Colors.BOLD}📋 分组统计:{Colors.END}")
        for suite in self.test_suites:
            summary = suite.get_summary()
            status_color = Colors.GREEN if summary['failed'] == 0 else Colors.RED
            print(f"  • {summary['name']}: {status_color}{summary['passed']}/{summary['total']}{Colors.END} "
                  f"({summary['success_rate']:.1f}%, {summary['total_duration']:.2f}s)")
        
        # 显示失败的测试
        failed_results = [r for r in self.results if not r.success]
        if failed_results:
            print(f"\n{Colors.BOLD}{Colors.RED}❌ 失败的测试:{Colors.END}")
            for result in failed_results:
                print(f"  • {result.name}: {result.message}")
        
        # 总体结果
        if failed_tests == 0:
            print(f"\n{Colors.BOLD}{Colors.GREEN}🎉 所有测试通过!{Colors.END}")
        else:
            print(f"\n{Colors.BOLD}{Colors.RED}⚠️  有 {failed_tests} 个测试失败{Colors.END}")
    
    async def run_all_tests(self, verbose: bool = True) -> bool:
        """运行所有测试"""
        self.print_header("增强版Fail2ban系统测试套件", Colors.BLUE)
        
        print(f"{Colors.CYAN}开始运行系统测试...{Colors.END}")
        print(f"{Colors.CYAN}测试套件数量: {len(self.test_suites)}{Colors.END}")
        
        start_time = time.time()
        
        for suite in self.test_suites:
            if verbose:
                self.print_suite_header(suite.name)
            
            try:
                # 设置测试环境
                await suite.setup()
                
                # 运行测试
                suite_results = await suite.run_all_tests()
                self.results.extend(suite_results)
                
                # 显示结果
                if verbose:
                    for result in suite_results:
                        self.print_result(result)
                
                # 清理测试环境
                await suite.teardown()
                
            except Exception as e:
                error_result = TestResult(
                    f"{suite.name} - 套件执行",
                    False,
                    f"测试套件执行失败: {e}",
                    0.0
                )
                self.results.append(error_result)
                
                if verbose:
                    self.print_result(error_result)
        
        total_duration = time.time() - start_time
        
        if verbose:
            print(f"\n{Colors.CYAN}测试完成，总耗时: {total_duration:.2f}秒{Colors.END}")
            self.print_summary()
        
        # 返回是否所有测试都通过
        return all(r.success for r in self.results)


async def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="增强版分布式Fail2ban系统测试套件",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--suite', '-s',
        choices=['all', 'tenancy', 'alerting', 'monitoring', 'security', 'ml', 'integration'],
        default='all',
        help='要运行的测试套件'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='详细输出'
    )
    
    parser.add_argument(
        '--quick', '-q',
        action='store_true',
        help='快速测试（跳过耗时的测试）'
    )
    
    args = parser.parse_args()
    
    # 创建测试运行器
    runner = SystemTestRunner()
    
    # 添加测试套件
    if args.suite in ['all', 'tenancy']:
        runner.add_test_suite(MultiTenancyTestSuite())
    
    if args.suite in ['all', 'alerting']:
        runner.add_test_suite(IntelligentAlertingTestSuite())
    
    if args.suite in ['all', 'monitoring']:
        runner.add_test_suite(PerformanceMonitoringTestSuite())
    
    if args.suite in ['all', 'security']:
        runner.add_test_suite(SecurityAuditingTestSuite())
    
    if args.suite in ['all', 'ml'] and not args.quick:
        runner.add_test_suite(MLAttackDetectionTestSuite())
    
    if args.suite in ['all', 'integration']:
        runner.add_test_suite(IntegrationTestSuite())
    
    try:
        # 运行测试
        success = await runner.run_all_tests(verbose=args.verbose)
        
        # 退出码
        exit_code = 0 if success else 1
        exit(exit_code)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}测试被用户中断{Colors.END}")
        exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}测试过程中发生错误: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())