#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 主启动脚本

该脚本用于启动分布式Fail2ban系统的各个组件
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from utils.logger import setup_logger
from utils.security import generate_api_key


class ConfigValidationError(Exception):
    """配置验证错误"""
    pass


class ServiceStartupError(Exception):
    """服务启动错误"""
    pass


class SystemManager:
    """系统管理器
    
    负责管理分布式Fail2ban系统的各个组件的启动、停止和监控
    """
    
    def __init__(self, config_path: str) -> None:
        """初始化系统管理器
        
        Args:
            config_path: 配置文件路径
            
        Raises:
            ConfigValidationError: 配置文件验证失败
            FileNotFoundError: 配置文件不存在
        """
        self.config_path: str = config_path
        self.config: Optional[Dict[str, Any]] = None
        self.logger: Optional[logging.Logger] = None
        self.running_services: List[Tuple[str, Any]] = []
        self.shutdown_event: asyncio.Event = asyncio.Event()
        
        # 加载配置
        self._load_config()
        
        # 验证配置
        self._validate_config()
        
        # 设置日志
        self._setup_logging()
        
        # 注册信号处理器
        self._setup_signal_handlers()
    
    def _load_config(self) -> None:
        """加载配置文件
        
        Raises:
            FileNotFoundError: 配置文件不存在
            yaml.YAMLError: YAML格式错误
            ConfigValidationError: 配置内容无效
        """
        try:
            if not os.path.exists(self.config_path):
                raise FileNotFoundError(f"配置文件不存在: {self.config_path}")
                
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
                
            if not isinstance(self.config, dict):
                raise ConfigValidationError("配置文件格式错误，应为字典格式")
                
            print(f"配置文件加载成功: {self.config_path}")
            
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"YAML格式错误: {e}")
        except Exception as e:
            print(f"配置文件加载失败: {e}")
            raise
    
    def _validate_config(self) -> None:
        """验证配置文件
        
        Raises:
            ConfigValidationError: 配置验证失败
        """
        if not self.config:
            raise ConfigValidationError("配置为空")
            
        required_sections = ['system', 'logging']
        for section in required_sections:
            if section not in self.config:
                raise ConfigValidationError(f"缺少必需的配置节: {section}")
        
        # 验证系统配置
        system_config = self.config.get('system', {})
        if 'mode' not in system_config:
            raise ConfigValidationError("缺少系统运行模式配置")
            
        valid_modes = ['central', 'agent', 'executor', 'all', 'enhanced']
        if system_config['mode'] not in valid_modes:
            raise ConfigValidationError(f"无效的运行模式: {system_config['mode']}")
    
    def _setup_logging(self) -> None:
        """设置日志
        
        Raises:
            Exception: 日志设置失败
        """
        try:
            log_config = self.config.get('logging', {})
            self.logger = setup_logger(
                'main',
                log_config.get('level', 'INFO'),
                log_config.get('file', 'logs/main.log')
            )
            self.logger.info("日志系统初始化成功")
        except Exception as e:
            print(f"日志设置失败: {e}")
            raise
    
    def _setup_signal_handlers(self) -> None:
        """设置信号处理器"""
        def signal_handler(signum: int, frame: Any) -> None:
            if self.logger:
                self.logger.info(f"接收到信号 {signum}，开始关闭系统...")
            else:
                print(f"接收到信号 {signum}，开始关闭系统...")
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def start_central_server(self) -> None:
        """启动中央控制服务器
        
        Raises:
            ServiceStartupError: 服务启动失败
        """
        try:
            from central.server import CentralServer
            
            self.logger.info("启动中央控制服务器...")
            
            # 验证中央服务器配置
            if 'central' not in self.config:
                raise ServiceStartupError("缺少中央服务器配置")
            
            server = CentralServer(self.config)
            await server.start()
            
            self.running_services.append(('central_server', server))
            self.logger.info("中央控制服务器启动成功")
            
        except ImportError as e:
            error_msg = f"无法导入中央服务器模块: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
        except Exception as e:
            error_msg = f"中央控制服务器启动失败: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
    
    async def start_log_agent(self) -> None:
        """启动日志收集代理
        
        Raises:
            ServiceStartupError: 服务启动失败
        """
        try:
            from agents.log_agent import LogAgent
            
            self.logger.info("启动日志收集代理...")
            
            # 验证代理配置
            if 'agent' not in self.config:
                raise ServiceStartupError("缺少代理配置")
            
            agent = LogAgent(self.config)
            await agent.start()
            
            self.running_services.append(('log_agent', agent))
            self.logger.info("日志收集代理启动成功")
            
        except ImportError as e:
            error_msg = f"无法导入日志代理模块: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
        except Exception as e:
            error_msg = f"日志收集代理启动失败: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
    
    async def start_executor(self) -> None:
        """启动执行节点
        
        Raises:
            ServiceStartupError: 服务启动失败
        """
        try:
            from central.executor import BanExecutor
            
            self.logger.info("启动执行节点...")
            
            # 验证执行器配置
            if 'executor' not in self.config:
                raise ServiceStartupError("缺少执行器配置")
            
            executor = BanExecutor(self.config)
            await executor.start()
            
            self.running_services.append(('executor', executor))
            self.logger.info("执行节点启动成功")
            
        except ImportError as e:
            error_msg = f"无法导入执行器模块: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
        except Exception as e:
            error_msg = f"执行节点启动失败: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
    
    async def start_web_dashboard(self) -> None:
        """启动Web仪表板
        
        Raises:
            ServiceStartupError: 服务启动失败
        """
        try:
            import uvicorn
            from web.dashboard import create_app
            
            self.logger.info("启动Web仪表板...")
            
            app = create_app(self.config)
            
            web_config = self.config.get('web', {})
            host = web_config.get('host', '0.0.0.0')
            port = web_config.get('port', 8080)
            
            # 验证端口范围
            if not (1 <= port <= 65535):
                raise ServiceStartupError(f"无效的端口号: {port}")
            
            config = uvicorn.Config(
                app,
                host=host,
                port=port,
                log_level="info"
            )
            
            server = uvicorn.Server(config)
            
            # 在后台启动服务器
            task = asyncio.create_task(server.serve())
            self.running_services.append(('web_dashboard', task))
            
            self.logger.info(f"Web仪表板启动成功: http://{host}:{port}")
            
        except ImportError as e:
            error_msg = f"无法导入Web模块: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
        except Exception as e:
            error_msg = f"Web仪表板启动失败: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
    
    async def start_enhanced_features(self) -> None:
        """启动增强功能模块
        
        Raises:
            ServiceStartupError: 服务启动失败
        """
        try:
            # 检查是否启用增强功能
            enhancements_config = self.config.get('enhancements', {})
            if not enhancements_config.get('enabled', False):
                self.logger.info("增强功能未启用")
                return
            
            from enhancements.enhanced_fail2ban import EnhancedFail2banSystem
            
            self.logger.info("启动增强功能模块...")
            
            # 创建增强系统实例
            enhanced_system = EnhancedFail2banSystem(
                str(self.config_path), 
                log_level=self.config.get('logging', {}).get('level', 'INFO')
            )
            
            # 启动增强系统
            await enhanced_system.start()
            
            self.running_services.append(('enhanced_features', enhanced_system))
            self.logger.info("增强功能模块启动成功")
            
        except ImportError as e:
            self.logger.warning(f"增强功能模块不可用: {e}")
        except Exception as e:
            error_msg = f"增强功能模块启动失败: {e}"
            self.logger.error(error_msg)
            raise ServiceStartupError(error_msg)
    
    async def run_mode(self, mode: str) -> None:
        """根据模式运行相应的服务
        
        Args:
            mode: 运行模式 (central, agent, executor, all, enhanced)
            
        Raises:
            ValueError: 无效的运行模式
            ServiceStartupError: 服务启动失败
        """
        self.logger.info(f"启动模式: {mode}")
        
        startup_tasks = []
        
        try:
            if mode == 'central':
                startup_tasks.extend([
                    self.start_central_server(),
                    self.start_web_dashboard()
                ])
            
            elif mode == 'agent':
                startup_tasks.append(self.start_log_agent())
            
            elif mode == 'executor':
                startup_tasks.append(self.start_executor())
            
            elif mode == 'enhanced':
                # 仅启动增强功能
                startup_tasks.append(self.start_enhanced_features())
            
            elif mode == 'all':
                startup_tasks.extend([
                    self.start_central_server(),
                    self.start_log_agent(),
                    self.start_executor(),
                    self.start_web_dashboard(),
                    self.start_enhanced_features()  # 添加增强功能
                ])
            
            else:
                raise ValueError(f"未知的运行模式: {mode}")
            
            # 并发启动所有服务
            if startup_tasks:
                await asyncio.gather(*startup_tasks)
            
            self.logger.info(f"所有服务启动完成，当前运行 {len(self.running_services)} 个服务")
            
            # 等待关闭信号
            await self.shutdown_event.wait()
            
        except Exception as e:
            self.logger.error(f"服务启动失败: {e}")
            await self.shutdown()
            raise
    
    async def shutdown(self) -> None:
        """关闭所有服务"""
        if self.logger:
            self.logger.info("开始关闭所有服务...")
        else:
            print("开始关闭所有服务...")
        
        # 关闭所有运行的服务
        shutdown_tasks = []
        
        for service_name, service in self.running_services:
            try:
                if self.logger:
                    self.logger.info(f"关闭服务: {service_name}")
                
                if hasattr(service, 'stop'):
                    shutdown_tasks.append(self._shutdown_service(service_name, service.stop()))
                elif hasattr(service, 'cancel'):
                    service.cancel()
                    shutdown_tasks.append(self._wait_for_cancelled_task(service_name, service))
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"准备关闭服务 {service_name} 时出错: {e}")
        
        # 并发关闭所有服务
        if shutdown_tasks:
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        
        self.running_services.clear()
        self.shutdown_event.set()
        
        if self.logger:
            self.logger.info("所有服务已关闭")
        else:
            print("所有服务已关闭")
    
    async def _shutdown_service(self, service_name: str, stop_coro: Any) -> None:
        """关闭单个服务
        
        Args:
            service_name: 服务名称
            stop_coro: 停止协程
        """
        try:
            await stop_coro
            if self.logger:
                self.logger.info(f"服务 {service_name} 已关闭")
        except Exception as e:
            if self.logger:
                self.logger.error(f"关闭服务 {service_name} 时出错: {e}")
    
    async def _wait_for_cancelled_task(self, service_name: str, task: asyncio.Task) -> None:
        """等待被取消的任务
        
        Args:
            service_name: 服务名称
            task: 任务对象
        """
        try:
            await task
        except asyncio.CancelledError:
            if self.logger:
                self.logger.info(f"服务 {service_name} 已取消")
        except Exception as e:
            if self.logger:
                self.logger.error(f"等待服务 {service_name} 取消时出错: {e}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """获取系统状态
        
        Returns:
            系统状态信息
        """
        return {
            'running_services': [name for name, _ in self.running_services],
            'service_count': len(self.running_services),
            'config_loaded': self.config is not None,
            'config_path': self.config_path,
            'logger_initialized': self.logger is not None,
            'shutdown_requested': self.shutdown_event.is_set(),
            'system_mode': self.config.get('system', {}).get('mode') if self.config else None
        }


def create_default_config(config_path: str = 'config.yaml') -> dict:
    """创建默认配置文件
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        dict: 默认配置字典
    """
    default_config = {
        'system': {
            'mode': 'central',
            'node_id': 'node-001',
            'region': 'default'
        },
        'logging': {
            'level': 'INFO',
            'file': 'logs/fail2ban.log',
            'max_size': '10MB',
            'backup_count': 5
        },
        'central': {
            'api': {
                'host': '0.0.0.0',
                'port': 8000,
                'api_key': generate_api_key()
            },
            'websocket': {
                'host': '0.0.0.0',
                'port': 8001
            },
            'database': {
                'redis': {
                    'host': 'localhost',
                    'port': 6379,
                    'db': 0
                },
                'mongodb': {
                    'host': 'localhost',
                    'port': 27017,
                    'database': 'fail2ban'
                }
            }
        },
        'agent': {
            'central_server': 'http://localhost:8000',
            'api_key': '',
            'nginx_logs': [
                '/var/log/nginx/access.log',
                '/var/log/nginx/error.log'
            ],
            'sender': {
                'batch_size': 100,
                'interval': 10,
                'retry_times': 3
            }
        },
        'executor': {
            'central_server': 'ws://localhost:8001',
            'api_key': '',
            'fail2ban': {
                'config_path': '/etc/fail2ban',
                'jail_name': 'nginx-distributed'
            }
        },
        'analysis': {
            'attack_patterns': {
                'sql_injection': {
                    'enabled': True,
                    'patterns': [
                        'union.*select',
                        'drop.*table',
                        'insert.*into',
                        'delete.*from'
                    ]
                },
                'xss': {
                    'enabled': True,
                    'patterns': [
                        '<script',
                        'javascript:',
                        'onerror=',
                        'onload='
                    ]
                },
                'path_traversal': {
                    'enabled': True,
                    'patterns': [
                        '\.\./\.\.',
                        '/etc/passwd',
                        '/etc/shadow',
                        'boot\.ini'
                    ]
                }
            },
            'ban_rules': {
                'attack_threshold': 5,
                'not_found_threshold': 20,
                'time_window': 10,
                'ban_duration': 3600,
                'risk_threshold': 70
            }
        },
        'whitelist': {
            'ips': ['127.0.0.1', '::1'],
            'networks': ['192.168.0.0/16', '10.0.0.0/8']
        },
        'notifications': {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from_email': '',
                'to_emails': []
            },
            'dingtalk': {
                'enabled': False,
                'webhook_url': '',
                'secret': ''
            },
            'wechat': {
                'enabled': False,
                'webhook_url': ''
            }
        },
        'web': {
            'host': '0.0.0.0',
            'port': 8080,
            'secret_key': generate_api_key()
        },
        'performance': {
            'max_workers': 4,
            'queue_size': 1000,
            'cleanup_interval': 3600
        },
        'enhancements': {
            'enabled': False,  # 设置为True启用增强功能
            'multi_tenancy': {
                'enabled': False,
                'admin_password': 'admin123'
            },
            'intelligent_alerting': {
                'enabled': False,
                'dynamic_threshold': True
            },
            'performance_monitoring': {
                'enabled': False,
                'trace_requests': True
            },
            'security_auditing': {
                'enabled': False,
                'compliance_reports': True
            },
            'ml_attack_detection': {
                'enabled': False,
                'auto_training': True
            },
            'web_interface': {
                'enabled': True,
                'host': '127.0.0.1',
                'port': 8080
            }
        }
    }
    
    # 确保目录存在
    if config_path != 'config.yaml':  # 只有在指定路径时才写入文件
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        # 写入配置文件
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)
        
        print(f"默认配置文件已创建: {config_path}")
        print("请根据实际环境修改配置文件中的相关参数")
    
    return default_config


def check_dependencies() -> bool:
    """检查依赖包"""
    required_packages = [
        'fastapi', 'uvicorn', 'websockets', 'aiohttp',
        'redis', 'pymongo', 'PyYAML', 'watchdog'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("缺少以下依赖包:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\n请运行以下命令安装依赖:")
        print("pip install -r requirements.txt")
        return False
    
    return True


def main() -> None:
    """主函数"""
    parser = argparse.ArgumentParser(
        description='分布式Fail2ban系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
运行模式说明:
  central  - 仅运行中央控制服务器和Web仪表板
  agent    - 仅运行日志收集代理
  executor - 仅运行封禁执行节点
  enhanced - 仅运行增强功能模块（多租户、智能告警、ML检测等）
  all      - 运行所有组件（适用于单机部署）

示例:
  python main.py --mode central --config config.yaml
  python main.py --mode enhanced --config config.yaml
  python main.py --mode all --config config.yaml
  python main.py --init-config
        """
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['central', 'agent', 'executor', 'all', 'enhanced'],
        default='central',
        help='运行模式 (默认: central)'
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='配置文件路径 (默认: config.yaml)'
    )
    
    parser.add_argument(
        '--init-config',
        action='store_true',
        help='创建默认配置文件'
    )
    
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='检查依赖包'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='分布式Fail2ban系统 v1.0.0'
    )
    
    args = parser.parse_args()
    
    # 检查依赖
    if args.check_deps:
        if check_dependencies():
            print("✅ 所有依赖包已安装")
        sys.exit(0)
    
    # 创建默认配置
    if args.init_config:
        create_default_config(args.config)
        sys.exit(0)
    
    # 检查配置文件是否存在
    if not os.path.exists(args.config):
        print(f"配置文件不存在: {args.config}")
        print("请使用 --init-config 创建默认配置文件")
        sys.exit(1)
    
    # 检查依赖包
    if not check_dependencies():
        sys.exit(1)
    
    # 创建系统管理器并运行
    try:
        manager = SystemManager(args.config)
        
        print(f"🚀 启动分布式Fail2ban系统")
        print(f"📁 配置文件: {args.config}")
        print(f"🔧 运行模式: {args.mode}")
        print(f"📊 系统状态: {manager.get_system_status()}")
        print("\n按 Ctrl+C 停止系统\n")
        
        # 运行系统
        asyncio.run(manager.run_mode(args.mode))
        
    except KeyboardInterrupt:
        print("\n👋 系统已停止")
    except Exception as e:
        print(f"❌ 系统启动失败: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()