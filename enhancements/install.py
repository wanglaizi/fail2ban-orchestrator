#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版分布式Fail2ban系统安装脚本

这个脚本提供自动化安装和配置功能，包括：
- 环境检查和依赖安装
- 配置文件生成
- 数据库初始化
- 服务配置
- 系统测试

作者: Fail2ban开发团队
版本: 2.0.0
许可: MIT License
"""

import os
import sys
import json
import yaml
import shutil
import subprocess
import argparse
import platform
import tempfile
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime


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
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class InstallationError(Exception):
    """安装错误异常"""
    pass


class EnhancedFail2banInstaller:
    """
    增强版Fail2ban系统安装器
    
    提供完整的安装、配置和部署功能。
    """
    
    def __init__(self, install_dir: str = None, config_file: str = None):
        """
        初始化安装器
        
        Args:
            install_dir: 安装目录
            config_file: 配置文件路径
        """
        self.install_dir = Path(install_dir) if install_dir else Path.cwd()
        self.config_file = config_file or "config.yaml"
        self.system_info = self._get_system_info()
        self.requirements = self._get_requirements()
        
        # 安装状态
        self.installation_log = []
        self.errors = []
        self.warnings = []
    
    def _get_system_info(self) -> Dict[str, str]:
        """
        获取系统信息
        
        Returns:
            系统信息字典
        """
        return {
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'python_implementation': platform.python_implementation()
        }
    
    def _get_requirements(self) -> List[str]:
        """
        获取依赖包列表
        
        Returns:
            依赖包名称列表
        """
        return [
            # Web框架
            'fastapi>=0.104.0',
            'uvicorn[standard]>=0.24.0',
            'websockets>=12.0',
            
            # HTTP客户端
            'aiohttp>=3.9.0',
            'requests>=2.31.0',
            
            # 数据库
            'redis>=5.0.0',
            'pymongo>=4.6.0',
            'motor>=3.3.0',
            'aiosqlite>=0.19.0',
            
            # 配置和序列化
            'PyYAML>=6.0.1',
            'pydantic>=2.5.0',
            
            # 日志和监控
            'watchdog>=3.0.0',
            'psutil>=5.9.0',
            
            # 安全
            'cryptography>=41.0.0',
            'passlib[bcrypt]>=1.7.4',
            'python-jose[cryptography]>=3.3.0',
            
            # 数据处理
            'numpy>=1.24.0',
            'pandas>=2.1.0',
            
            # 机器学习
            'scikit-learn>=1.3.0',
            
            # 网络和地理位置
            'geoip2>=4.7.0',
            'maxminddb>=2.2.0',
            
            # 模板引擎
            'jinja2>=3.1.0',
            
            # 开发工具
            'pytest>=7.4.0',
            'pytest-asyncio>=0.21.0',
            'flake8>=6.1.0',
            'black>=23.0.0'
        ]
    
    def log(self, message: str, level: str = "INFO") -> None:
        """
        记录安装日志
        
        Args:
            message: 日志消息
            level: 日志级别
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {level}: {message}"
        
        self.installation_log.append(log_entry)
        
        # 根据级别选择颜色
        color = {
            'INFO': Colors.GREEN,
            'WARNING': Colors.YELLOW,
            'ERROR': Colors.RED,
            'DEBUG': Colors.CYAN
        }.get(level, Colors.WHITE)
        
        print(f"{color}{log_entry}{Colors.END}")
        
        if level == "ERROR":
            self.errors.append(message)
        elif level == "WARNING":
            self.warnings.append(message)
    
    def print_header(self, title: str) -> None:
        """
        打印标题
        
        Args:
            title: 标题文本
        """
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{title:^60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")
    
    def check_python_version(self) -> bool:
        """
        检查Python版本
        
        Returns:
            是否满足版本要求
        """
        self.log("检查Python版本...")
        
        version = sys.version_info
        required_version = (3, 8)
        
        if version >= required_version:
            self.log(f"✓ Python版本: {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            self.log(
                f"✗ Python版本过低: {version.major}.{version.minor}.{version.micro}, "
                f"需要 >= {required_version[0]}.{required_version[1]}",
                "ERROR"
            )
            return False
    
    def check_system_requirements(self) -> bool:
        """
        检查系统要求
        
        Returns:
            是否满足系统要求
        """
        self.log("检查系统要求...")
        
        # 检查操作系统
        system = platform.system()
        if system not in ['Linux', 'Darwin', 'Windows']:
            self.log(f"✗ 不支持的操作系统: {system}", "ERROR")
            return False
        
        self.log(f"✓ 操作系统: {system}")
        
        # 检查内存
        try:
            import psutil
            memory = psutil.virtual_memory()
            memory_gb = memory.total / (1024**3)
            
            if memory_gb < 1:
                self.log(f"⚠ 内存较少: {memory_gb:.1f}GB，建议至少2GB", "WARNING")
            else:
                self.log(f"✓ 内存: {memory_gb:.1f}GB")
        except ImportError:
            self.log("⚠ 无法检查内存信息", "WARNING")
        
        # 检查磁盘空间
        try:
            disk_usage = shutil.disk_usage(self.install_dir)
            free_gb = disk_usage.free / (1024**3)
            
            if free_gb < 1:
                self.log(f"✗ 磁盘空间不足: {free_gb:.1f}GB，需要至少1GB", "ERROR")
                return False
            else:
                self.log(f"✓ 可用磁盘空间: {free_gb:.1f}GB")
        except Exception as e:
            self.log(f"⚠ 无法检查磁盘空间: {e}", "WARNING")
        
        return True
    
    def check_network_connectivity(self) -> bool:
        """
        检查网络连接
        
        Returns:
            网络是否可用
        """
        self.log("检查网络连接...")
        
        try:
            import urllib.request
            urllib.request.urlopen('https://pypi.org', timeout=10)
            self.log("✓ 网络连接正常")
            return True
        except Exception as e:
            self.log(f"✗ 网络连接失败: {e}", "ERROR")
            return False
    
    def install_dependencies(self, force: bool = False) -> bool:
        """
        安装依赖包
        
        Args:
            force: 是否强制重新安装
        
        Returns:
            安装是否成功
        """
        self.log("安装Python依赖包...")
        
        try:
            # 升级pip
            self.log("升级pip...")
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'
            ], check=True, capture_output=True, text=True)
            
            # 安装依赖
            for requirement in self.requirements:
                self.log(f"安装 {requirement}...")
                
                cmd = [sys.executable, '-m', 'pip', 'install']
                if force:
                    cmd.append('--force-reinstall')
                cmd.append(requirement)
                
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )
                
                if result.returncode != 0:
                    self.log(f"✗ 安装 {requirement} 失败: {result.stderr}", "ERROR")
                    return False
                else:
                    self.log(f"✓ 已安装 {requirement}")
            
            self.log("✓ 所有依赖包安装完成")
            return True
            
        except subprocess.TimeoutExpired:
            self.log("✗ 安装超时", "ERROR")
            return False
        except Exception as e:
            self.log(f"✗ 安装依赖包失败: {e}", "ERROR")
            return False
    
    def create_directory_structure(self) -> bool:
        """
        创建目录结构
        
        Returns:
            创建是否成功
        """
        self.log("创建目录结构...")
        
        directories = [
            'config',
            'logs',
            'data',
            'data/ml_models',
            'data/geoip',
            'data/backups',
            'data/exports',
            'static',
            'templates',
            'scripts'
        ]
        
        try:
            for directory in directories:
                dir_path = self.install_dir / directory
                dir_path.mkdir(parents=True, exist_ok=True)
                self.log(f"✓ 创建目录: {dir_path}")
            
            return True
            
        except Exception as e:
            self.log(f"✗ 创建目录结构失败: {e}", "ERROR")
            return False
    
    def generate_config_file(self, interactive: bool = True) -> bool:
        """
        生成配置文件
        
        Args:
            interactive: 是否交互式配置
        
        Returns:
            生成是否成功
        """
        self.log("生成配置文件...")
        
        try:
            config = self._create_base_config()
            
            if interactive:
                config = self._interactive_config(config)
            
            # 写入配置文件
            config_path = self.install_dir / self.config_file
            
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            
            self.log(f"✓ 配置文件已生成: {config_path}")
            return True
            
        except Exception as e:
            self.log(f"✗ 生成配置文件失败: {e}", "ERROR")
            return False
    
    def _create_base_config(self) -> Dict:
        """
        创建基础配置
        
        Returns:
            基础配置字典
        """
        # 生成随机密钥
        secret_key = secrets.token_urlsafe(32)
        encryption_key = secrets.token_urlsafe(32)[:32]  # 32字符长度
        
        return {
            "system": {
                "debug": False,
                "log_level": "INFO",
                "secret_key": secret_key,
                "data_dir": str(self.install_dir / "data"),
                "log_dir": str(self.install_dir / "logs")
            },
            "multi_tenancy": {
                "enabled": True,
                "storage": {
                    "type": "sqlite",
                    "db_path": str(self.install_dir / "data" / "tenants.db")
                },
                "admin_password": "admin123",
                "session_timeout": 3600,
                "default_quota": {
                    "max_banned_ips": 1000,
                    "max_rules": 50,
                    "max_users": 10,
                    "max_storage_mb": 100
                }
            },
            "intelligent_alerting": {
                "enabled": True,
                "anomaly_detection": {
                    "enabled": True,
                    "algorithm": "isolation_forest",
                    "contamination": 0.1,
                    "training_interval": 3600
                },
                "dynamic_thresholds": {
                    "enabled": True,
                    "adaptation_rate": 0.1,
                    "min_samples": 100
                },
                "alert_suppression": {
                    "enabled": True,
                    "window_minutes": 5,
                    "max_alerts_per_window": 10
                }
            },
            "performance_monitoring": {
                "enabled": True,
                "collection_interval": 60,
                "metrics_retention_days": 30,
                "distributed_tracing": {
                    "enabled": True,
                    "sample_rate": 0.1
                },
                "thresholds": {
                    "cpu_percent": 80,
                    "memory_percent": 85,
                    "disk_percent": 90,
                    "response_time_ms": 1000
                }
            },
            "security_auditing": {
                "enabled": True,
                "encryption_key": encryption_key,
                "audit_log_path": str(self.install_dir / "data" / "audit.db"),
                "retention_days": 90,
                "threat_intelligence": {
                    "enabled": True,
                    "update_interval": 3600,
                    "sources": []
                },
                "compliance": {
                    "standards": ["PCI_DSS", "GDPR"],
                    "report_interval": 86400
                }
            },
            "ml_attack_detection": {
                "enabled": True,
                "models_dir": str(self.install_dir / "data" / "ml_models"),
                "training": {
                    "auto_training": True,
                    "training_interval": 86400,
                    "min_samples": 1000
                },
                "models": [
                    {
                        "name": "random_forest",
                        "type": "RandomForest",
                        "enabled": True,
                        "weight": 0.4,
                        "config": {
                            "n_estimators": 100,
                            "max_depth": 10
                        }
                    },
                    {
                        "name": "anomaly_detection",
                        "type": "AnomalyDetection",
                        "enabled": True,
                        "weight": 0.3,
                        "config": {
                            "contamination": 0.1
                        }
                    }
                ],
                "ensemble": {
                    "enabled": True,
                    "voting": "weighted",
                    "threshold": 0.7
                }
            },
            "data_sources": {
                "file_sources": [
                    {
                        "name": "nginx_access",
                        "type": "file",
                        "enabled": False,
                        "path": "/var/log/nginx/access.log",
                        "format": "nginx",
                        "encoding": "utf-8"
                    },
                    {
                        "name": "apache_access",
                        "type": "file",
                        "enabled": False,
                        "path": "/var/log/apache2/access.log",
                        "format": "apache",
                        "encoding": "utf-8"
                    }
                ],
                "redis_sources": []
            },
            "notification_channels": {
                "email": {
                    "type": "email",
                    "enabled": False,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "from_email": "",
                    "to_emails": [],
                    "use_tls": True
                },
                "webhook": {
                    "type": "webhook",
                    "enabled": True,
                    "webhook_url": "http://httpbin.org/post",
                    "timeout": 30,
                    "rate_limit": 60
                }
            },
            "web_interface": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 8080,
                "ssl": {
                    "enabled": False,
                    "cert_file": "",
                    "key_file": ""
                },
                "cors": {
                    "enabled": True,
                    "origins": ["*"]
                }
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file_logging": {
                    "enabled": True,
                    "log_file": str(self.install_dir / "logs" / "fail2ban.log"),
                    "max_size_mb": 10,
                    "backup_count": 5
                }
            },
            "caching": {
                "type": "memory",
                "redis": {
                    "host": "localhost",
                    "port": 6379,
                    "db": 0,
                    "password": ""
                }
            },
            "database": {
                "mongodb": {
                    "enabled": False,
                    "host": "localhost",
                    "port": 27017,
                    "database": "fail2ban",
                    "username": "",
                    "password": ""
                }
            },
            "backup": {
                "enabled": True,
                "backup_dir": str(self.install_dir / "data" / "backups"),
                "schedule": "0 2 * * *",
                "retention_days": 30,
                "compress": True
            },
            "health_check": {
                "enabled": True,
                "interval": 300,
                "endpoints": [
                    "http://127.0.0.1:8080/health"
                ]
            }
        }
    
    def _interactive_config(self, config: Dict) -> Dict:
        """
        交互式配置
        
        Args:
            config: 基础配置
        
        Returns:
            更新后的配置
        """
        print(f"\n{Colors.CYAN}=== 交互式配置 ==={Colors.END}")
        print("按回车键使用默认值，输入新值进行修改\n")
        
        # Web界面配置
        print(f"{Colors.YELLOW}Web管理界面配置:{Colors.END}")
        
        host = input(f"监听地址 [{config['web_interface']['host']}]: ").strip()
        if host:
            config['web_interface']['host'] = host
        
        port = input(f"监听端口 [{config['web_interface']['port']}]: ").strip()
        if port and port.isdigit():
            config['web_interface']['port'] = int(port)
        
        # 管理员密码
        print(f"\n{Colors.YELLOW}管理员账户配置:{Colors.END}")
        
        admin_password = input(f"管理员密码 [{config['multi_tenancy']['admin_password']}]: ").strip()
        if admin_password:
            config['multi_tenancy']['admin_password'] = admin_password
        
        # 邮件通知配置
        print(f"\n{Colors.YELLOW}邮件通知配置 (可选):{Colors.END}")
        
        enable_email = input("启用邮件通知? [y/N]: ").strip().lower()
        if enable_email in ['y', 'yes']:
            config['notification_channels']['email']['enabled'] = True
            
            smtp_server = input("SMTP服务器: ").strip()
            if smtp_server:
                config['notification_channels']['email']['smtp_server'] = smtp_server
            
            username = input("邮箱用户名: ").strip()
            if username:
                config['notification_channels']['email']['username'] = username
                config['notification_channels']['email']['from_email'] = username
            
            password = input("邮箱密码: ").strip()
            if password:
                config['notification_channels']['email']['password'] = password
            
            to_emails = input("接收邮箱 (多个用逗号分隔): ").strip()
            if to_emails:
                config['notification_channels']['email']['to_emails'] = [
                    email.strip() for email in to_emails.split(',')
                ]
        
        # 日志文件配置
        print(f"\n{Colors.YELLOW}日志文件配置:{Colors.END}")
        
        log_sources = input("日志文件路径 (多个用逗号分隔): ").strip()
        if log_sources:
            sources = []
            for i, path in enumerate(log_sources.split(',')):
                path = path.strip()
                if path:
                    source_name = f"custom_log_{i+1}"
                    log_format = "common"
                    
                    if 'nginx' in path.lower():
                        log_format = "nginx"
                    elif 'apache' in path.lower():
                        log_format = "apache"
                    
                    sources.append({
                        "name": source_name,
                        "type": "file",
                        "enabled": True,
                        "path": path,
                        "format": log_format,
                        "encoding": "utf-8"
                    })
            
            config['data_sources']['file_sources'].extend(sources)
        
        return config
    
    def create_startup_scripts(self) -> bool:
        """
        创建启动脚本
        
        Returns:
            创建是否成功
        """
        self.log("创建启动脚本...")
        
        try:
            scripts_dir = self.install_dir / "scripts"
            
            # 创建启动脚本
            if platform.system() == "Windows":
                self._create_windows_scripts(scripts_dir)
            else:
                self._create_unix_scripts(scripts_dir)
            
            self.log("✓ 启动脚本创建完成")
            return True
            
        except Exception as e:
            self.log(f"✗ 创建启动脚本失败: {e}", "ERROR")
            return False
    
    def _create_windows_scripts(self, scripts_dir: Path) -> None:
        """
        创建Windows启动脚本
        
        Args:
            scripts_dir: 脚本目录
        """
        # 启动脚本
        start_script = scripts_dir / "start.bat"
        with open(start_script, 'w', encoding='utf-8') as f:
            f.write(f"""@echo off
cd /d "{self.install_dir}"
python -m enhancements.enhanced_fail2ban --config {self.config_file}
pause
""")
        
        # 停止脚本
        stop_script = scripts_dir / "stop.bat"
        with open(stop_script, 'w', encoding='utf-8') as f:
            f.write("""@echo off
taskkill /f /im python.exe
echo System stopped.
pause
""")
        
        # 安装服务脚本
        install_service_script = scripts_dir / "install_service.bat"
        with open(install_service_script, 'w', encoding='utf-8') as f:
            f.write(f"""@echo off
echo Installing Enhanced Fail2ban Service...
sc create "EnhancedFail2ban" binPath= "python {self.install_dir / 'enhancements' / 'enhanced_fail2ban.py'} --config {self.config_file}" start= auto
echo Service installed successfully.
pause
""")
    
    def _create_unix_scripts(self, scripts_dir: Path) -> None:
        """
        创建Unix启动脚本
        
        Args:
            scripts_dir: 脚本目录
        """
        # 启动脚本
        start_script = scripts_dir / "start.sh"
        with open(start_script, 'w', encoding='utf-8') as f:
            f.write(f"""#!/bin/bash
cd "{self.install_dir}"
python3 -m enhancements.enhanced_fail2ban --config {self.config_file}
""")
        start_script.chmod(0o755)
        
        # 停止脚本
        stop_script = scripts_dir / "stop.sh"
        with open(stop_script, 'w', encoding='utf-8') as f:
            f.write("""#!/bin/bash
pkill -f "enhanced_fail2ban"
echo "System stopped."
""")
        stop_script.chmod(0o755)
        
        # 系统服务脚本
        service_script = scripts_dir / "enhanced-fail2ban.service"
        with open(service_script, 'w', encoding='utf-8') as f:
            f.write(f"""[Unit]
Description=Enhanced Fail2ban System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={self.install_dir}
ExecStart={sys.executable} -m enhancements.enhanced_fail2ban --config {self.config_file}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
""")
    
    def run_tests(self) -> bool:
        """
        运行系统测试
        
        Returns:
            测试是否通过
        """
        self.log("运行系统测试...")
        
        try:
            # 测试配置文件加载
            config_path = self.install_dir / self.config_file
            with open(config_path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
            self.log("✓ 配置文件格式正确")
            
            # 测试模块导入
            test_modules = [
                'enhancements.multi_tenancy',
                'enhancements.intelligent_alerting',
                'enhancements.performance_monitoring',
                'enhancements.security_auditing',
                'enhancements.ml_attack_detection',
                'enhancements.multi_datasource_notification',
                'enhancements.gui_config_interface'
            ]
            
            for module in test_modules:
                try:
                    __import__(module)
                    self.log(f"✓ 模块导入成功: {module}")
                except ImportError as e:
                    self.log(f"⚠ 模块导入失败: {module} - {e}", "WARNING")
            
            # 测试数据库连接
            try:
                import sqlite3
                db_path = self.install_dir / "data" / "test.db"
                conn = sqlite3.connect(str(db_path))
                conn.close()
                db_path.unlink(missing_ok=True)
                self.log("✓ SQLite数据库测试通过")
            except Exception as e:
                self.log(f"⚠ SQLite数据库测试失败: {e}", "WARNING")
            
            self.log("✓ 系统测试完成")
            return True
            
        except Exception as e:
            self.log(f"✗ 系统测试失败: {e}", "ERROR")
            return False
    
    def install(self, interactive: bool = True, force: bool = False) -> bool:
        """
        执行完整安装
        
        Args:
            interactive: 是否交互式安装
            force: 是否强制重新安装
        
        Returns:
            安装是否成功
        """
        self.print_header("增强版分布式Fail2ban系统安装")
        
        print(f"{Colors.CYAN}安装目录: {self.install_dir}{Colors.END}")
        print(f"{Colors.CYAN}配置文件: {self.config_file}{Colors.END}")
        print(f"{Colors.CYAN}Python版本: {platform.python_version()}{Colors.END}")
        print(f"{Colors.CYAN}操作系统: {platform.system()} {platform.release()}{Colors.END}\n")
        
        if interactive and not force:
            confirm = input(f"{Colors.YELLOW}确认开始安装? [Y/n]: {Colors.END}").strip().lower()
            if confirm in ['n', 'no']:
                self.log("安装已取消")
                return False
        
        # 安装步骤
        steps = [
            ("检查Python版本", self.check_python_version),
            ("检查系统要求", self.check_system_requirements),
            ("检查网络连接", self.check_network_connectivity),
            ("安装依赖包", lambda: self.install_dependencies(force)),
            ("创建目录结构", self.create_directory_structure),
            ("生成配置文件", lambda: self.generate_config_file(interactive)),
            ("创建启动脚本", self.create_startup_scripts),
            ("运行系统测试", self.run_tests)
        ]
        
        for step_name, step_func in steps:
            self.print_header(step_name)
            
            if not step_func():
                self.log(f"✗ {step_name}失败，安装中止", "ERROR")
                return False
        
        # 安装完成
        self.print_installation_summary()
        return True
    
    def print_installation_summary(self) -> None:
        """
        打印安装摘要
        """
        self.print_header("安装完成")
        
        print(f"{Colors.GREEN}🎉 增强版Fail2ban系统安装成功!{Colors.END}\n")
        
        print(f"{Colors.BOLD}安装信息:{Colors.END}")
        print(f"  📁 安装目录: {self.install_dir}")
        print(f"  ⚙️  配置文件: {self.install_dir / self.config_file}")
        print(f"  📝 日志目录: {self.install_dir / 'logs'}")
        print(f"  💾 数据目录: {self.install_dir / 'data'}")
        
        print(f"\n{Colors.BOLD}启动方式:{Colors.END}")
        if platform.system() == "Windows":
            print(f"  🚀 双击运行: {self.install_dir / 'scripts' / 'start.bat'}")
            print(f"  💻 命令行: python -m enhancements.enhanced_fail2ban --config {self.config_file}")
        else:
            print(f"  🚀 脚本启动: {self.install_dir / 'scripts' / 'start.sh'}")
            print(f"  💻 命令行: python3 -m enhancements.enhanced_fail2ban --config {self.config_file}")
        
        # Web界面信息
        try:
            config_path = self.install_dir / self.config_file
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            if config.get('web_interface', {}).get('enabled', True):
                host = config['web_interface'].get('host', '127.0.0.1')
                port = config['web_interface'].get('port', 8080)
                print(f"\n{Colors.BOLD}Web管理界面:{Colors.END}")
                print(f"  🌐 访问地址: http://{host}:{port}")
                print(f"  👤 管理员账户: admin")
                print(f"  🔑 管理员密码: {config.get('multi_tenancy', {}).get('admin_password', 'admin123')}")
        except Exception:
            pass
        
        print(f"\n{Colors.BOLD}下一步:{Colors.END}")
        print(f"  1. 根据需要修改配置文件")
        print(f"  2. 配置日志文件路径和通知渠道")
        print(f"  3. 启动系统并访问Web管理界面")
        print(f"  4. 创建租户和用户账户")
        
        if self.warnings:
            print(f"\n{Colors.YELLOW}⚠️  警告信息:{Colors.END}")
            for warning in self.warnings:
                print(f"  • {warning}")
        
        print(f"\n{Colors.CYAN}📚 更多信息请查看: {self.install_dir / 'enhancements' / 'README.md'}{Colors.END}")
        print(f"{Colors.CYAN}🐛 问题反馈: https://github.com/wanglaizi/fail2ban-orchestrator/issues{Colors.END}")
    
    def save_installation_log(self) -> None:
        """
        保存安装日志
        """
        try:
            log_file = self.install_dir / "logs" / "installation.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(self.installation_log))
            
            print(f"\n📝 安装日志已保存: {log_file}")
            
        except Exception as e:
            print(f"⚠️  保存安装日志失败: {e}")


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(
        description="增强版分布式Fail2ban系统安装器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  %(prog)s                                    # 交互式安装到当前目录
  %(prog)s --install-dir /opt/fail2ban       # 安装到指定目录
  %(prog)s --non-interactive                 # 非交互式安装
  %(prog)s --force                           # 强制重新安装
  %(prog)s --config custom.yaml              # 使用自定义配置文件名
        """
    )
    
    parser.add_argument(
        '--install-dir', '-d',
        type=str,
        help='安装目录 (默认: 当前目录)'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='config.yaml',
        help='配置文件名 (默认: config.yaml)'
    )
    
    parser.add_argument(
        '--non-interactive', '-n',
        action='store_true',
        help='非交互式安装'
    )
    
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='强制重新安装'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='增强版Fail2ban系统安装器 v2.0.0'
    )
    
    args = parser.parse_args()
    
    # 创建安装器
    installer = EnhancedFail2banInstaller(
        install_dir=args.install_dir,
        config_file=args.config
    )
    
    try:
        # 执行安装
        success = installer.install(
            interactive=not args.non_interactive,
            force=args.force
        )
        
        # 保存安装日志
        installer.save_installation_log()
        
        if success:
            print(f"\n{Colors.GREEN}✅ 安装成功完成!{Colors.END}")
            sys.exit(0)
        else:
            print(f"\n{Colors.RED}❌ 安装失败!{Colors.END}")
            if installer.errors:
                print(f"\n{Colors.RED}错误信息:{Colors.END}")
                for error in installer.errors:
                    print(f"  • {error}")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}安装已取消{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}安装过程中发生错误: {e}{Colors.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()