#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 增强功能模块

提供多租户、智能告警、性能监控、安全审计、机器学习检测等增强功能。
"""

__version__ = "2.0.0"
__author__ = "Fail2ban开发团队"

# 导出主要的增强功能类
try:
    from .multi_tenancy import MultiTenancyManager, UserRole, Permission
    from .intelligent_alerting import IntelligentAlertingSystem, AlertSeverity, AlertType
    from .performance_monitoring import PerformanceMonitor, get_performance_monitor, trace_function
    from .security_auditing import SecurityAuditingSystem, SecurityEventType, SecurityLevel
    from .ml_attack_detection import MLAttackDetectionSystem
    from .multi_datasource_notification import MultiDataSourceManager, NotificationMessage
    from .gui_config_interface import GUIConfigInterface
    from .enhanced_fail2ban import EnhancedFail2banSystem
    
    __all__ = [
        'MultiTenancyManager', 'UserRole', 'Permission',
        'IntelligentAlertingSystem', 'AlertSeverity', 'AlertType',
        'PerformanceMonitor', 'get_performance_monitor', 'trace_function',
        'SecurityAuditingSystem', 'SecurityEventType', 'SecurityLevel',
        'MLAttackDetectionSystem',
        'MultiDataSourceManager', 'NotificationMessage',
        'GUIConfigInterface',
        'EnhancedFail2banSystem'
    ]
except ImportError as e:
    # 如果某些模块不存在，只导出可用的
    __all__ = []
    print(f"警告: 部分增强功能模块导入失败: {e}")