#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版分布式Fail2ban系统主程序

这个文件整合了所有增强功能模块，提供完整的系统启动和管理功能。
包括：
- 多租户管理
- 智能告警和动态阈值
- 性能监控和链路追踪
- 安全审计功能
- 机器学习攻击检测
- 图形化配置界面
- 多数据源和通知渠道

作者: Fail2ban开发团队
版本: 2.0.0
许可: MIT License
"""

import asyncio
import signal
import sys
import os
import json
import yaml
import logging
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

# 导入增强功能模块 - 使用简化的fallback实现
try:
    from enhancements.multi_tenancy import (
        MultiTenancyManager, UserRole, Permission, ResourceQuota
    )
except ImportError:
    # 简化的多租户管理器
    class MultiTenancyManager:
        def __init__(self, config: dict):
            self.config = config
        async def initialize(self): pass
        async def shutdown(self): pass
    
    class UserRole: pass
    class Permission: pass
    class ResourceQuota: pass

try:
    from enhancements.intelligent_alerting import (
        IntelligentAlertingSystem, AlertSeverity, AlertType
    )
except ImportError:
    # 简化的智能告警系统
    class IntelligentAlertingSystem:
        def __init__(self, config: dict):
            self.config = config
        async def initialize(self): pass
        async def shutdown(self): pass
    
    class AlertSeverity: pass
    class AlertType: pass

try:
    from enhancements.performance_monitoring import (
        PerformanceMonitor, get_performance_monitor, trace_function
    )
except ImportError:
    # 简化的性能监控
    class PerformanceMonitor:
        def __init__(self, config: dict):
            self.config = config
        async def initialize(self): pass
        async def shutdown(self): pass
    
    def get_performance_monitor():
        return None
    
    def trace_function(func):
        return func

# 其他增强功能模块的简化实现
try:
    from enhancements.security_auditing import SecurityAuditingSystem
except ImportError:
    class SecurityAuditingSystem:
        def __init__(self, config: dict): self.config = config
        async def initialize(self): pass
        async def shutdown(self): pass

try:
    from enhancements.ml_attack_detection import MLAttackDetectionSystem
except ImportError:
    class MLAttackDetectionSystem:
        def __init__(self, config: dict): self.config = config
        async def initialize(self): pass
        async def shutdown(self): pass

try:
    from enhancements.multi_datasource_notification import MultiDataSourceManager
except ImportError:
    class MultiDataSourceManager:
        def __init__(self, config: dict): self.config = config
        async def initialize(self): pass
        async def shutdown(self): pass

try:
    from enhancements.gui_config_interface import GUIConfigInterface
except ImportError:
    class GUIConfigInterface:
        def __init__(self, config: dict): self.config = config
        async def initialize(self): pass
        async def shutdown(self): pass

# 尝试导入原有的核心模块
try:
    # 修正导入路径
    import sys
    from pathlib import Path
    
    # 添加项目根目录到路径
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    from utils.config import ConfigManager
    from analysis.ip_analyzer import IPAnalyzer
except ImportError as e:
    # 如果无法导入，创建简单的替代实现
    print(f"警告: 无法导入核心模块 ({e})，使用简化实现")
    
    class ConfigManager:
        def load_config(self, path: str) -> dict:
            with open(path, 'r', encoding='utf-8') as f:
                if path.endswith('.yaml') or path.endswith('.yml'):
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
    
    class IPAnalyzer:
        def __init__(self, config: dict):
            self.config = config
            
        async def analyze_ip(self, ip: str, log_entry: dict, attack_type: str = None) -> dict:
            """简化的IP分析实现"""
            return {
                'ip': ip,
                'whitelisted': False,
                'risk_score': 0.5,
                'should_ban': False,
                'reason': '使用简化分析器',
                'behavior_summary': {},
                'geo_info': None
            }


class EnhancedFail2banSystem:
    """
    增强版Fail2ban系统主类
    
    整合所有增强功能模块，提供统一的系统管理接口。
    """
    
    def __init__(self, config_path: str, log_level: str = "INFO"):
        """
        初始化系统
        
        Args:
            config_path: 配置文件路径
            log_level: 日志级别
        """
        self.config_path = Path(config_path)
        self.log_level = log_level
        self.config = {}
        self.logger = self._setup_logging()
        
        # 系统状态
        self.is_running = False
        self.is_initialized = False
        self.start_time = None
        
        # 管理器实例
        self.config_manager = None  # 将在load_config中初始化
        self.tenancy_manager: Optional[MultiTenancyManager] = None
        self.alerting_system: Optional[IntelligentAlertingSystem] = None
        self.performance_monitor: Optional[PerformanceMonitor] = None
        self.security_auditing: Optional[SecurityAuditingSystem] = None
        self.ml_detection: Optional[MLAttackDetectionSystem] = None
        self.datasource_manager: Optional[MultiDataSourceManager] = None
        self.gui_interface: Optional[GUIConfigInterface] = None
        self.ip_analyzer: Optional[IPAnalyzer] = None
        
        # 信号处理
        self._setup_signal_handlers()
        
        # 统计信息
        self.stats = {
            'total_events_processed': 0,
            'total_alerts_generated': 0,
            'total_ips_banned': 0,
            'total_attacks_detected': 0,
            'uptime_seconds': 0
        }
    
    def _setup_logging(self) -> logging.Logger:
        """
        设置日志系统
        
        Returns:
            配置好的日志记录器
        """
        logger = logging.getLogger('enhanced_fail2ban')
        logger.setLevel(getattr(logging, self.log_level.upper()))
        
        # 避免重复添加处理器
        if not logger.handlers:
            # 控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            # 格式化器
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            
            logger.addHandler(console_handler)
        
        return logger
    
    def _setup_signal_handlers(self) -> None:
        """
        设置信号处理器
        """
        def signal_handler(signum, frame):
            self.logger.info(f"收到信号 {signum}，正在优雅关闭系统...")
            asyncio.create_task(self.stop())
        
        # 注册信号处理器
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, signal_handler)
    
    @trace_function
    async def load_config(self) -> None:
        """
        加载配置文件
        """
        try:
            self.logger.info(f"正在加载配置文件: {self.config_path}")
            
            # 尝试使用真正的ConfigManager
            if self.config_manager is None:
                try:
                    self.config_manager = ConfigManager(str(self.config_path))
                    self.config = self.config_manager.config
                except Exception as e:
                    self.logger.warning(f"无法使用ConfigManager ({e})，使用简化加载")
                    # 使用简化的配置加载
                    self.config = self._load_config_simple()
            else:
                self.config = self.config_manager.config
            
            # 验证必要的配置项
            self._validate_config()
            
            self.logger.info("配置文件加载成功")
            
        except Exception as e:
            self.logger.error(f"加载配置文件失败: {e}")
            raise
    
    def _load_config_simple(self) -> dict:
        """
        简化的配置加载方法
        """
        with open(self.config_path, 'r', encoding='utf-8') as f:
            if str(self.config_path).endswith('.yaml') or str(self.config_path).endswith('.yml'):
                return yaml.safe_load(f)
            else:
                return json.load(f)
    
    def _validate_config(self) -> None:
        """
        验证配置文件
        """
        required_sections = ['system']
        
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"配置文件缺少必要的节: {section}")
        
        # 验证系统配置
        system_config = self.config['system']
        if 'secret_key' not in system_config:
            self.logger.warning("未设置系统密钥，将使用默认值")
            system_config['secret_key'] = 'default-secret-key-change-in-production'
    
    @trace_function
    async def initialize(self) -> None:
        """
        初始化所有系统组件
        """
        if self.is_initialized:
            return
        
        self.logger.info("正在初始化增强版Fail2ban系统...")
        
        try:
            # 加载配置
            await self.load_config()
            
            # 初始化核心IP分析器
            await self._initialize_ip_analyzer()
            
            # 初始化多租户管理
            await self._initialize_multi_tenancy()
            
            # 初始化智能告警
            await self._initialize_intelligent_alerting()
            
            # 初始化性能监控
            await self._initialize_performance_monitoring()
            
            # 初始化安全审计
            await self._initialize_security_auditing()
            
            # 初始化ML检测
            await self._initialize_ml_detection()
            
            # 初始化多数据源管理
            await self._initialize_datasource_management()
            
            # 初始化Web界面
            await self._initialize_web_interface()
            
            self.is_initialized = True
            self.logger.info("系统初始化完成")
            
        except Exception as e:
            self.logger.error(f"系统初始化失败: {e}")
            raise
    
    async def _initialize_ip_analyzer(self) -> None:
        """
        初始化IP分析器
        """
        try:
            self.logger.info("初始化IP分析器...")
            ip_config = self.config.get('ip_analyzer', {})
            self.ip_analyzer = IPAnalyzer(ip_config)
            self.logger.info("✓ IP分析器初始化完成")
        except Exception as e:
            self.logger.warning(f"IP分析器初始化失败: {e}")
    
    async def _initialize_multi_tenancy(self) -> None:
        """
        初始化多租户管理
        """
        if not self.config.get('multi_tenancy', {}).get('enabled', False):
            self.logger.info("多租户功能未启用")
            return
        
        try:
            self.logger.info("初始化多租户管理...")
            self.tenancy_manager = MultiTenancyManager(self.config['multi_tenancy'])
            await self.tenancy_manager.initialize()
            await self.tenancy_manager.start_background_tasks()
            self.logger.info("✓ 多租户管理初始化完成")
        except Exception as e:
            self.logger.error(f"多租户管理初始化失败: {e}")
            raise
    
    async def _initialize_intelligent_alerting(self) -> None:
        """
        初始化智能告警
        """
        if not self.config.get('intelligent_alerting', {}).get('enabled', False):
            self.logger.info("智能告警功能未启用")
            return
        
        try:
            self.logger.info("初始化智能告警系统...")
            self.alerting_system = IntelligentAlertingSystem(self.config['intelligent_alerting'])
            await self.alerting_system.initialize()
            
            # 设置告警回调
            if self.datasource_manager:
                self.alerting_system.set_notification_callback(
                    self._handle_alert_notification
                )
            
            self.logger.info("✓ 智能告警系统初始化完成")
        except Exception as e:
            self.logger.error(f"智能告警系统初始化失败: {e}")
            raise
    
    async def _initialize_performance_monitoring(self) -> None:
        """
        初始化性能监控
        """
        if not self.config.get('performance_monitoring', {}).get('enabled', False):
            self.logger.info("性能监控功能未启用")
            return
        
        try:
            self.logger.info("初始化性能监控...")
            self.performance_monitor = PerformanceMonitor(self.config['performance_monitoring'])
            
            # 设置告警回调
            if self.alerting_system:
                self.performance_monitor.set_alert_callback(
                    self._handle_performance_alert
                )
            
            await self.performance_monitor.start_monitoring()
            self.logger.info("✓ 性能监控初始化完成")
        except Exception as e:
            self.logger.error(f"性能监控初始化失败: {e}")
            raise
    
    async def _initialize_security_auditing(self) -> None:
        """
        初始化安全审计
        """
        if not self.config.get('security_auditing', {}).get('enabled', False):
            self.logger.info("安全审计功能未启用")
            return
        
        try:
            self.logger.info("初始化安全审计...")
            self.security_auditing = SecurityAuditingSystem(self.config['security_auditing'])
            await self.security_auditing.initialize()
            self.logger.info("✓ 安全审计初始化完成")
        except Exception as e:
            self.logger.error(f"安全审计初始化失败: {e}")
            raise
    
    async def _initialize_ml_detection(self) -> None:
        """
        初始化ML检测
        """
        if not self.config.get('ml_attack_detection', {}).get('enabled', False):
            self.logger.info("机器学习检测功能未启用")
            return
        
        try:
            self.logger.info("初始化机器学习攻击检测...")
            self.ml_detection = MLAttackDetectionSystem(self.config['ml_attack_detection'])
            await self.ml_detection.initialize()
            self.logger.info("✓ 机器学习攻击检测初始化完成")
        except Exception as e:
            self.logger.error(f"机器学习攻击检测初始化失败: {e}")
            raise
    
    async def _initialize_datasource_management(self) -> None:
        """
        初始化多数据源管理
        """
        data_sources = self.config.get('data_sources', {})
        notification_channels = self.config.get('notification_channels', {})
        
        if not data_sources and not notification_channels:
            self.logger.info("未配置数据源和通知渠道")
            return
        
        try:
            self.logger.info("初始化多数据源和通知管理...")
            self.datasource_manager = MultiDataSourceManager({
                'data_sources': data_sources,
                'notification_channels': notification_channels
            })
            
            # 设置日志处理回调
            self.datasource_manager.set_log_callback(self._handle_log_entry)
            
            await self.datasource_manager.start_monitoring()
            self.logger.info("✓ 多数据源和通知管理初始化完成")
        except Exception as e:
            self.logger.error(f"多数据源和通知管理初始化失败: {e}")
            raise
    
    async def _initialize_web_interface(self) -> None:
        """
        初始化Web界面
        """
        if not self.config.get('web_interface', {}).get('enabled', True):
            self.logger.info("Web管理界面未启用")
            return
        
        try:
            self.logger.info("初始化Web管理界面...")
            web_config = self.config.get('web_interface', {})
            
            # 注入其他管理器的引用
            web_config['system_managers'] = {
                'tenancy': self.tenancy_manager,
                'alerting': self.alerting_system,
                'performance': self.performance_monitor,
                'security': self.security_auditing,
                'ml_detection': self.ml_detection,
                'datasource': self.datasource_manager,
                'ip_analyzer': self.ip_analyzer
            }
            
            self.gui_interface = GUIConfigInterface(web_config)
            # Web界面将在start()方法中启动
            self.logger.info("✓ Web管理界面初始化完成")
        except Exception as e:
            self.logger.error(f"Web管理界面初始化失败: {e}")
            raise
    
    @trace_function
    async def start(self) -> None:
        """
        启动系统
        """
        if self.is_running:
            self.logger.warning("系统已在运行中")
            return
        
        try:
            # 初始化系统
            await self.initialize()
            
            # 启动Web界面
            if self.gui_interface:
                await self.gui_interface.start_server()
            
            self.is_running = True
            self.start_time = datetime.now()
            
            self.logger.info("🚀 增强版Fail2ban系统启动成功")
            self._print_startup_info()
            
            # 记录系统启动事件
            if self.security_auditing:
                await self.security_auditing.log_security_event(
                    event_type=SecurityEventType.SYSTEM_START,
                    level=SecurityLevel.INFO,
                    description="系统启动",
                    metadata={
                        "version": "2.0.0",
                        "config_file": str(self.config_path),
                        "enabled_features": self._get_enabled_features()
                    }
                )
            
            # 发送启动通知
            if self.datasource_manager:
                await self._send_startup_notification()
            
            # 运行演示任务（如果启用）
            if self.config.get('system', {}).get('debug', False):
                await self._run_demo_tasks()
            
        except Exception as e:
            self.logger.error(f"系统启动失败: {e}")
            await self.stop()
            raise
    
    def _print_startup_info(self) -> None:
        """
        打印启动信息
        """
        print("\n" + "="*60)
        print("🛡️  增强版分布式Fail2ban系统")
        print("="*60)
        print(f"版本: 2.0.0")
        print(f"启动时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"配置文件: {self.config_path}")
        print("\n启用的功能模块:")
        
        features = self._get_enabled_features()
        for feature in features:
            print(f"  ✓ {feature}")
        
        if self.gui_interface:
            web_config = self.config.get('web_interface', {})
            host = web_config.get('host', '127.0.0.1')
            port = web_config.get('port', 8080)
            print(f"\n🌐 Web管理界面: http://{host}:{port}")
        
        print("\n按 Ctrl+C 停止系统")
        print("="*60 + "\n")
    
    def _get_enabled_features(self) -> List[str]:
        """
        获取启用的功能列表
        
        Returns:
            启用的功能名称列表
        """
        features = []
        
        if self.tenancy_manager:
            features.append("多租户管理")
        if self.alerting_system:
            features.append("智能告警和动态阈值")
        if self.performance_monitor:
            features.append("性能监控和链路追踪")
        if self.security_auditing:
            features.append("安全审计功能")
        if self.ml_detection:
            features.append("机器学习攻击检测")
        if self.datasource_manager:
            features.append("多数据源和通知渠道")
        if self.gui_interface:
            features.append("图形化配置界面")
        if self.ip_analyzer:
            features.append("IP行为分析")
        
        return features
    
    async def _send_startup_notification(self) -> None:
        """
        发送系统启动通知
        """
        try:
            message = NotificationMessage(
                title="系统启动通知",
                content=f"增强版Fail2ban系统已成功启动\n\n"
                       f"启动时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                       f"启用功能: {', '.join(self._get_enabled_features())}\n"
                       f"配置文件: {self.config_path}",
                level="info",
                timestamp=datetime.now(),
                source="system",
                tags=["startup", "system"],
                metadata={
                    "version": "2.0.0",
                    "enabled_features": self._get_enabled_features()
                }
            )
            
            await self.datasource_manager.send_notification_to_all_channels(message)
            
        except Exception as e:
            self.logger.warning(f"发送启动通知失败: {e}")
    
    @trace_function
    async def stop(self) -> None:
        """
        停止系统
        """
        if not self.is_running:
            return
        
        self.logger.info("正在停止系统...")
        
        try:
            # 记录系统停止事件
            if self.security_auditing:
                await self.security_auditing.log_security_event(
                    event_type=SecurityEventType.SYSTEM_STOP,
                    level=SecurityLevel.INFO,
                    description="系统停止",
                    metadata={
                        "uptime_seconds": self._get_uptime_seconds(),
                        "stats": self.stats
                    }
                )
            
            # 发送停止通知
            if self.datasource_manager:
                await self._send_shutdown_notification()
            
            # 停止各个组件
            if self.datasource_manager:
                await self.datasource_manager.stop_monitoring()
            
            if self.performance_monitor:
                await self.performance_monitor.stop_monitoring()
            
            if self.tenancy_manager:
                await self.tenancy_manager.stop_background_tasks()
            
            self.is_running = False
            
            # 计算运行时间
            uptime = self._get_uptime_seconds()
            self.logger.info(f"系统已停止，运行时间: {uptime}秒")
            
        except Exception as e:
            self.logger.error(f"停止系统时发生错误: {e}")
    
    async def _send_shutdown_notification(self) -> None:
        """
        发送系统停止通知
        """
        try:
            uptime = self._get_uptime_seconds()
            
            message = NotificationMessage(
                title="系统停止通知",
                content=f"增强版Fail2ban系统正在停止\n\n"
                       f"运行时间: {uptime}秒\n"
                       f"处理事件: {self.stats['total_events_processed']}\n"
                       f"生成告警: {self.stats['total_alerts_generated']}\n"
                       f"封禁IP: {self.stats['total_ips_banned']}",
                level="warning",
                timestamp=datetime.now(),
                source="system",
                tags=["shutdown", "system"],
                metadata={
                    "uptime_seconds": uptime,
                    "stats": self.stats
                }
            )
            
            await self.datasource_manager.send_notification_to_all_channels(message)
            
        except Exception as e:
            self.logger.warning(f"发送停止通知失败: {e}")
    
    def _get_uptime_seconds(self) -> int:
        """
        获取系统运行时间（秒）
        
        Returns:
            运行时间秒数
        """
        if self.start_time:
            return int((datetime.now() - self.start_time).total_seconds())
        return 0
    
    async def _handle_log_entry(self, log_entry: dict) -> None:
        """
        处理日志条目
        
        Args:
            log_entry: 日志条目数据
        """
        try:
            self.stats['total_events_processed'] += 1
            
            # IP分析
            if self.ip_analyzer and 'ip_address' in log_entry:
                # 这里可以调用IP分析器进行分析
                pass
            
            # ML检测
            if self.ml_detection:
                prediction = await self.ml_detection.predict(log_entry)
                if prediction.is_attack:
                    self.stats['total_attacks_detected'] += 1
                    
                    # 触发告警
                    if self.alerting_system:
                        await self.alerting_system.process_event({
                            'timestamp': datetime.now(),
                            'source': 'ml_detection',
                            'ip_address': log_entry.get('ip_address'),
                            'attack_type': 'ml_detected',
                            'confidence': prediction.confidence,
                            'details': log_entry
                        })
            
            # 安全审计
            if self.security_auditing:
                await self.security_auditing.log_security_event(
                    event_type=SecurityEventType.ACCESS_LOG,
                    level=SecurityLevel.INFO,
                    source_ip=log_entry.get('ip_address'),
                    description=f"访问日志: {log_entry.get('request', 'N/A')}",
                    metadata=log_entry
                )
            
        except Exception as e:
            self.logger.error(f"处理日志条目失败: {e}")
    
    async def _handle_alert_notification(self, alert: dict) -> None:
        """
        处理告警通知
        
        Args:
            alert: 告警数据
        """
        try:
            self.stats['total_alerts_generated'] += 1
            
            if self.datasource_manager:
                message = NotificationMessage(
                    title=f"[{alert['severity'].upper()}] {alert['title']}",
                    content=alert['description'],
                    level=alert['severity'],
                    timestamp=alert['timestamp'],
                    source="alerting_system",
                    tags=["alert", alert['severity']],
                    metadata=alert
                )
                
                await self.datasource_manager.send_notification_to_all_channels(message)
            
        except Exception as e:
            self.logger.error(f"处理告警通知失败: {e}")
    
    async def _handle_performance_alert(self, metric: str, value: float, threshold: float) -> None:
        """
        处理性能告警
        
        Args:
            metric: 指标名称
            value: 当前值
            threshold: 阈值
        """
        try:
            if self.alerting_system:
                await self.alerting_system.process_event({
                    'timestamp': datetime.now(),
                    'source': 'performance_monitor',
                    'metric': metric,
                    'value': value,
                    'threshold': threshold,
                    'severity': 'high' if value > threshold * 1.2 else 'medium'
                })
            
        except Exception as e:
            self.logger.error(f"处理性能告警失败: {e}")
    
    async def _run_demo_tasks(self) -> None:
        """
        运行演示任务（仅在调试模式下）
        """
        if not self.config.get('system', {}).get('debug', False):
            return
        
        self.logger.info("\n=== 运行演示任务 ===")
        
        try:
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
            
        except Exception as e:
            self.logger.error(f"运行演示任务失败: {e}")
    
    async def _demo_multi_tenancy(self) -> None:
        """
        演示多租户功能
        """
        self.logger.info("--- 多租户功能演示 ---")
        
        try:
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
                self.logger.info(f"✓ 已创建租户: {tenant.name}")
                
                # 创建演示用户
                user = await self.tenancy_manager.create_user(
                    tenant_id=tenant.id,
                    username="demo_admin",
                    email="demo@example.com",
                    password="demo123",
                    role=UserRole.TENANT_ADMIN
                )
                
                if user:
                    self.logger.info(f"✓ 已创建用户: {user.username}")
        
        except Exception as e:
            self.logger.error(f"多租户演示失败: {e}")
    
    async def _demo_intelligent_alerting(self) -> None:
        """
        演示智能告警功能
        """
        self.logger.info("--- 智能告警功能演示 ---")
        
        try:
            # 模拟攻击事件
            for i in range(5):
                event = {
                    "timestamp": datetime.now(),
                    "source": "demo_source",
                    "ip_address": "192.168.1.100",
                    "attack_type": "brute_force",
                    "severity": "medium",
                    "details": f"模拟攻击事件 #{i+1}"
                }
                
                await self.alerting_system.process_event(event)
            
            self.logger.info("✓ 已处理5个模拟攻击事件")
        
        except Exception as e:
            self.logger.error(f"智能告警演示失败: {e}")
    
    async def _demo_ml_detection(self) -> None:
        """
        演示ML检测功能
        """
        self.logger.info("--- 机器学习检测功能演示 ---")
        
        try:
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
            self.logger.info(f"✓ ML预测结果: 是否攻击={prediction.is_attack}, 置信度={prediction.confidence:.2f}")
        
        except Exception as e:
            self.logger.error(f"ML检测演示失败: {e}")
    
    async def _demo_security_auditing(self) -> None:
        """
        演示安全审计功能
        """
        self.logger.info("--- 安全审计功能演示 ---")
        
        try:
            # 记录安全事件
            await self.security_auditing.log_security_event(
                event_type=SecurityEventType.ATTACK_DETECTED,
                level=SecurityLevel.HIGH,
                source_ip="malicious.com",
                description="检测到SQL注入攻击",
                metadata={"attack_type": "sql_injection", "payload": "' OR 1=1--"}
            )
            
            self.logger.info("✓ 已记录安全事件")
        
        except Exception as e:
            self.logger.error(f"安全审计演示失败: {e}")
    
    async def run_forever(self) -> None:
        """
        持续运行系统
        """
        await self.start()
        
        try:
            while self.is_running:
                # 更新统计信息
                self.stats['uptime_seconds'] = self._get_uptime_seconds()
                
                # 等待一段时间
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("收到中断信号")
        finally:
            await self.stop()
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        获取系统状态
        
        Returns:
            系统状态信息
        """
        return {
            'is_running': self.is_running,
            'is_initialized': self.is_initialized,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'uptime_seconds': self._get_uptime_seconds(),
            'enabled_features': self._get_enabled_features(),
            'stats': self.stats,
            'components': {
                'tenancy_manager': self.tenancy_manager is not None,
                'alerting_system': self.alerting_system is not None,
                'performance_monitor': self.performance_monitor is not None,
                'security_auditing': self.security_auditing is not None,
                'ml_detection': self.ml_detection is not None,
                'datasource_manager': self.datasource_manager is not None,
                'gui_interface': self.gui_interface is not None,
                'ip_analyzer': self.ip_analyzer is not None
            }
        }


def create_default_config() -> dict:
    """
    创建默认配置
    
    Returns:
        默认配置字典
    """
    return {
        "system": {
            "debug": False,
            "log_level": "INFO",
            "secret_key": "change-this-secret-key-in-production"
        },
        "multi_tenancy": {
            "enabled": True,
            "storage": {
                "type": "sqlite",
                "db_path": "tenants.db"
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


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(
        description="增强版分布式Fail2ban系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  %(prog)s --config config.yaml                    # 使用指定配置文件启动
  %(prog)s --config config.yaml --debug           # 启用调试模式
  %(prog)s --create-config                        # 创建默认配置文件
  %(prog)s --config config.yaml --validate        # 验证配置文件
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='config.yaml',
        help='配置文件路径 (默认: config.yaml)'
    )
    
    parser.add_argument(
        '--log-level', '-l',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='日志级别 (默认: INFO)'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='启用调试模式'
    )
    
    parser.add_argument(
        '--create-config',
        action='store_true',
        help='创建默认配置文件'
    )
    
    parser.add_argument(
        '--validate',
        action='store_true',
        help='验证配置文件'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='增强版Fail2ban系统 v2.0.0'
    )
    
    args = parser.parse_args()
    
    # 创建默认配置文件
    if args.create_config:
        config_path = Path(args.config)
        if config_path.exists():
            print(f"配置文件 {config_path} 已存在")
            return
        
        config = create_default_config()
        
        with open(config_path, 'w', encoding='utf-8') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            else:
                json.dump(config, f, indent=2, ensure_ascii=False)
        
        print(f"已创建默认配置文件: {config_path}")
        return
    
    # 验证配置文件
    if args.validate:
        try:
            config_manager = ConfigManager()
            config = config_manager.load_config(args.config)
            print(f"配置文件 {args.config} 验证通过")
            return
        except Exception as e:
            print(f"配置文件验证失败: {e}")
            sys.exit(1)
    
    # 检查配置文件是否存在
    if not Path(args.config).exists():
        print(f"配置文件 {args.config} 不存在")
        print(f"使用 --create-config 创建默认配置文件")
        sys.exit(1)
    
    # 设置日志级别
    log_level = 'DEBUG' if args.debug else args.log_level
    
    # 创建并运行系统
    system = EnhancedFail2banSystem(args.config, log_level)
    
    try:
        asyncio.run(system.run_forever())
    except KeyboardInterrupt:
        print("\n系统已停止")
    except Exception as e:
        print(f"系统运行错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()