#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 主启动脚本

该脚本用于启动分布式Fail2ban系统的各个组件
"""

import argparse
import asyncio
import os
import signal
import sys
import yaml
from pathlib import Path
from typing import Dict, Optional

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from utils.logger import setup_logger
from utils.security import generate_api_key


class SystemManager:
    """系统管理器"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = None
        self.logger = None
        self.running_services = []
        self.shutdown_event = asyncio.Event()
        
        # 加载配置
        self._load_config()
        
        # 设置日志
        self._setup_logging()
        
        # 注册信号处理器
        self._setup_signal_handlers()
    
    def _load_config(self):
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            print(f"配置文件加载成功: {self.config_path}")
        except Exception as e:
            print(f"配置文件加载失败: {e}")
            sys.exit(1)
    
    def _setup_logging(self):
        """设置日志"""
        log_config = self.config.get('logging', {})
        self.logger = setup_logger(
            'main',
            log_config.get('level', 'INFO'),
            log_config.get('file', 'logs/main.log')
        )
    
    def _setup_signal_handlers(self):
        """设置信号处理器"""
        def signal_handler(signum, frame):
            self.logger.info(f"接收到信号 {signum}，开始关闭系统...")
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def start_central_server(self):
        """启动中央控制服务器"""
        try:
            from central.server import CentralServer
            
            self.logger.info("启动中央控制服务器...")
            
            server = CentralServer(self.config)
            await server.start()
            
            self.running_services.append(('central_server', server))
            self.logger.info("中央控制服务器启动成功")
            
        except Exception as e:
            self.logger.error(f"中央控制服务器启动失败: {e}")
            raise
    
    async def start_log_agent(self):
        """启动日志收集代理"""
        try:
            from agents.log_agent import LogAgent
            
            self.logger.info("启动日志收集代理...")
            
            agent = LogAgent(self.config)
            await agent.start()
            
            self.running_services.append(('log_agent', agent))
            self.logger.info("日志收集代理启动成功")
            
        except Exception as e:
            self.logger.error(f"日志收集代理启动失败: {e}")
            raise
    
    async def start_executor(self):
        """启动执行节点"""
        try:
            from central.executor import BanExecutor
            
            self.logger.info("启动执行节点...")
            
            executor = BanExecutor(self.config)
            await executor.start()
            
            self.running_services.append(('executor', executor))
            self.logger.info("执行节点启动成功")
            
        except Exception as e:
            self.logger.error(f"执行节点启动失败: {e}")
            raise
    
    async def start_web_dashboard(self):
        """启动Web仪表板"""
        try:
            import uvicorn
            from web.dashboard import create_app
            
            self.logger.info("启动Web仪表板...")
            
            app = create_app(self.config)
            
            web_config = self.config.get('web', {})
            host = web_config.get('host', '0.0.0.0')
            port = web_config.get('port', 8080)
            
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
            
        except Exception as e:
            self.logger.error(f"Web仪表板启动失败: {e}")
            raise
    
    async def run_mode(self, mode: str):
        """根据模式运行相应的服务
        
        Args:
            mode: 运行模式 (central, agent, executor, all)
        """
        self.logger.info(f"启动模式: {mode}")
        
        try:
            if mode == 'central':
                await self.start_central_server()
                await self.start_web_dashboard()
            
            elif mode == 'agent':
                await self.start_log_agent()
            
            elif mode == 'executor':
                await self.start_executor()
            
            elif mode == 'all':
                await self.start_central_server()
                await self.start_log_agent()
                await self.start_executor()
                await self.start_web_dashboard()
            
            else:
                raise ValueError(f"未知的运行模式: {mode}")
            
            # 等待关闭信号
            await self.shutdown_event.wait()
            
        except Exception as e:
            self.logger.error(f"服务启动失败: {e}")
            await self.shutdown()
            raise
    
    async def shutdown(self):
        """关闭所有服务"""
        self.logger.info("开始关闭所有服务...")
        
        # 关闭所有运行的服务
        for service_name, service in self.running_services:
            try:
                self.logger.info(f"关闭服务: {service_name}")
                
                if hasattr(service, 'stop'):
                    await service.stop()
                elif hasattr(service, 'cancel'):
                    service.cancel()
                    try:
                        await service
                    except asyncio.CancelledError:
                        pass
                
                self.logger.info(f"服务 {service_name} 已关闭")
                
            except Exception as e:
                self.logger.error(f"关闭服务 {service_name} 时出错: {e}")
        
        self.running_services.clear()
        self.shutdown_event.set()
        self.logger.info("所有服务已关闭")
    
    def get_system_status(self) -> Dict:
        """获取系统状态
        
        Returns:
            系统状态信息
        """
        return {
            'running_services': [name for name, _ in self.running_services],
            'config_loaded': self.config is not None,
            'logger_initialized': self.logger is not None,
            'shutdown_requested': self.shutdown_event.is_set()
        }


def create_default_config(config_path: str):
    """创建默认配置文件
    
    Args:
        config_path: 配置文件路径
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
        }
    }
    
    # 确保目录存在
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    # 写入配置文件
    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)
    
    print(f"默认配置文件已创建: {config_path}")
    print("请根据实际环境修改配置文件中的相关参数")


def check_dependencies():
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


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='分布式Fail2ban系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
运行模式说明:
  central  - 仅运行中央控制服务器和Web仪表板
  agent    - 仅运行日志收集代理
  executor - 仅运行封禁执行节点
  all      - 运行所有组件（适用于单机部署）

示例:
  python main.py --mode central --config config.yaml
  python main.py --mode agent --config config.yaml
  python main.py --init-config
        """
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['central', 'agent', 'executor', 'all'],
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