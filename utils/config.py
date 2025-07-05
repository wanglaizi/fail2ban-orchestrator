#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 配置管理工具

提供统一的配置加载、验证、管理和更新功能
"""

import json
import os
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Set
from datetime import datetime
import ipaddress


class ConfigError(Exception):
    """配置相关错误基类"""
    pass


class ConfigValidationError(ConfigError):
    """配置验证错误"""
    pass


class ConfigLoadError(ConfigError):
    """配置加载错误"""
    pass


class ConfigSaveError(ConfigError):
    """配置保存错误"""
    pass


class ConfigManager:
    """配置管理器
    
    提供配置文件的加载、验证、保存和管理功能
    """
    
    def __init__(self, config_path: str) -> None:
        """初始化配置管理器
        
        Args:
            config_path: 配置文件路径
            
        Raises:
            ConfigLoadError: 配置文件加载失败
        """
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self._schema = self._get_config_schema()
        
        # 加载配置
        self.load_config()
    
    def load_config(self) -> None:
        """加载配置文件
        
        Raises:
            ConfigLoadError: 配置文件加载失败
            ConfigValidationError: 配置验证失败
        """
        try:
            if not self.config_path.exists():
                raise ConfigLoadError(f"配置文件不存在: {self.config_path}")
            
            if not self.config_path.is_file():
                raise ConfigLoadError(f"路径不是文件: {self.config_path}")
            
            # 检查文件权限
            if not os.access(self.config_path, os.R_OK):
                raise ConfigLoadError(f"配置文件无读取权限: {self.config_path}")
            
            # 根据文件扩展名选择解析器
            if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                self.config = self._load_yaml()
            elif self.config_path.suffix.lower() == '.json':
                self.config = self._load_json()
            else:
                raise ConfigLoadError(f"不支持的配置文件格式: {self.config_path.suffix}")
            
            # 验证配置
            self.validate_config()
            
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ConfigLoadError(f"配置文件格式错误: {e}")
        except Exception as e:
            if isinstance(e, (ConfigLoadError, ConfigValidationError)):
                raise
            raise ConfigLoadError(f"加载配置文件失败: {e}")
    
    def _load_yaml(self) -> Dict[str, Any]:
        """加载YAML配置文件
        
        Returns:
            配置字典
            
        Raises:
            yaml.YAMLError: YAML解析错误
        """
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            
        if not isinstance(config, dict):
            raise ConfigLoadError("配置文件根节点必须是字典")
            
        return config
    
    def _load_json(self) -> Dict[str, Any]:
        """加载JSON配置文件
        
        Returns:
            配置字典
            
        Raises:
            json.JSONDecodeError: JSON解析错误
        """
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            
        if not isinstance(config, dict):
            raise ConfigLoadError("配置文件根节点必须是字典")
            
        return config
    
    def save_config(self, backup: bool = True) -> None:
        """保存配置文件
        
        Args:
            backup: 是否创建备份
            
        Raises:
            ConfigSaveError: 保存失败
        """
        try:
            # 验证配置
            self.validate_config()
            
            # 创建备份
            if backup and self.config_path.exists():
                backup_path = self.config_path.with_suffix(
                    f"{self.config_path.suffix}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )
                backup_path.write_bytes(self.config_path.read_bytes())
            
            # 确保目录存在
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 保存配置
            if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                self._save_yaml()
            elif self.config_path.suffix.lower() == '.json':
                self._save_json()
            else:
                raise ConfigSaveError(f"不支持的配置文件格式: {self.config_path.suffix}")
                
        except Exception as e:
            if isinstance(e, (ConfigSaveError, ConfigValidationError)):
                raise
            raise ConfigSaveError(f"保存配置文件失败: {e}")
    
    def _save_yaml(self) -> None:
        """保存为YAML格式
        
        Raises:
            ConfigSaveError: 保存失败
        """
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(
                    self.config, 
                    f, 
                    default_flow_style=False, 
                    allow_unicode=True,
                    indent=2,
                    sort_keys=False
                )
        except Exception as e:
            raise ConfigSaveError(f"保存YAML文件失败: {e}")
    
    def _save_json(self) -> None:
        """保存为JSON格式
        
        Raises:
            ConfigSaveError: 保存失败
        """
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(
                    self.config, 
                    f, 
                    ensure_ascii=False, 
                    indent=2,
                    separators=(',', ': ')
                )
        except Exception as e:
            raise ConfigSaveError(f"保存JSON文件失败: {e}")
    
    def validate_config(self) -> None:
        """验证配置文件
        
        Raises:
            ConfigValidationError: 配置验证失败
        """
        if not self.config:
            raise ConfigValidationError("配置为空")
        
        # 验证必需的顶级节
        required_sections = self._schema.get('required_sections', [])
        for section in required_sections:
            if section not in self.config:
                raise ConfigValidationError(f"缺少必需的配置节: {section}")
        
        # 验证各个配置节
        self._validate_system_config()
        self._validate_logging_config()
        self._validate_network_config()
        self._validate_security_config()
        
        # 验证模式特定配置
        mode = self.get('system.mode')
        if mode == 'central':
            self._validate_central_config()
        elif mode == 'agent':
            self._validate_agent_config()
        elif mode == 'executor':
            self._validate_executor_config()
        elif mode == 'web':
            self._validate_web_config()
    
    def _validate_system_config(self) -> None:
        """验证系统配置
        
        Raises:
            ConfigValidationError: 验证失败
        """
        system_config = self.config.get('system', {})
        
        # 验证运行模式
        mode = system_config.get('mode')
        valid_modes = {'central', 'agent', 'executor', 'web', 'all'}
        if not mode or mode not in valid_modes:
            raise ConfigValidationError(
                f"无效的运行模式: {mode}，有效值: {valid_modes}"
            )
        
        # 验证节点ID
        node_id = system_config.get('node_id')
        if not node_id or not isinstance(node_id, str):
            raise ConfigValidationError("节点ID必须是非空字符串")
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', node_id):
            raise ConfigValidationError("节点ID只能包含字母、数字、下划线和连字符")
    
    def _validate_logging_config(self) -> None:
        """验证日志配置
        
        Raises:
            ConfigValidationError: 验证失败
        """
        logging_config = self.config.get('logging', {})
        
        # 验证日志级别
        level = logging_config.get('level', 'INFO')
        valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        if level.upper() not in valid_levels:
            raise ConfigValidationError(
                f"无效的日志级别: {level}，有效值: {valid_levels}"
            )
        
        # 验证日志文件路径
        log_file = logging_config.get('file')
        if log_file:
            log_path = Path(log_file)
            if not log_path.parent.exists():
                try:
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    raise ConfigValidationError(f"无法创建日志目录: {e}")
    
    def _validate_network_config(self) -> None:
        """验证网络配置
        
        Raises:
            ConfigValidationError: 验证失败
        """
        # 验证中央服务器配置
        if 'central' in self.config:
            central_config = self.config['central']
            
            # 验证主机地址
            host = central_config.get('host', '0.0.0.0')
            if host != '0.0.0.0':
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    raise ConfigValidationError(f"无效的主机地址: {host}")
            
            # 验证端口
            port = central_config.get('port', 5000)
            if not isinstance(port, int) or not (1 <= port <= 65535):
                raise ConfigValidationError(f"无效的端口号: {port}")
    
    def _validate_security_config(self) -> None:
        """验证安全配置
        
        Raises:
            ConfigValidationError: 验证失败
        """
        security_config = self.config.get('security', {})
        
        # 验证API密钥
        api_key = security_config.get('api_key')
        if api_key and len(api_key) < 16:
            raise ConfigValidationError("API密钥长度不能少于16个字符")
        
        # 验证白名单IP
        whitelist = security_config.get('whitelist_ips', [])
        for ip in whitelist:
            try:
                ipaddress.ip_network(ip, strict=False)
            except ValueError:
                raise ConfigValidationError(f"无效的白名单IP: {ip}")
    
    def _validate_central_config(self) -> None:
        """验证中央节点配置"""
        if 'central' not in self.config:
            raise ConfigValidationError("中央模式需要central配置节")
        
        central_config = self.config['central']
        
        # 验证数据库配置
        if 'database' in central_config:
            db_config = central_config['database']
            
            # Redis配置
            if 'redis' in db_config:
                redis_config = db_config['redis']
                port = redis_config.get('port', 6379)
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    raise ConfigValidationError(f"无效的Redis端口: {port}")
            
            # MongoDB配置
            if 'mongodb' in db_config:
                mongo_config = db_config['mongodb']
                port = mongo_config.get('port', 27017)
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    raise ConfigValidationError(f"无效的MongoDB端口: {port}")
    
    def _validate_agent_config(self) -> None:
        """验证代理节点配置"""
        if 'agent' not in self.config:
            raise ConfigValidationError("代理模式需要agent配置节")
        
        agent_config = self.config['agent']
        
        # 验证中央服务器地址
        central_server = agent_config.get('central_server')
        if not central_server:
            raise ConfigValidationError("代理节点必须配置central_server")
        
        # 验证日志文件路径
        if 'nginx' in agent_config:
            nginx_config = agent_config['nginx']
            access_log = nginx_config.get('access_log')
            if access_log and not Path(access_log).exists():
                raise ConfigValidationError(f"Nginx访问日志文件不存在: {access_log}")
    
    def _validate_executor_config(self) -> None:
        """验证执行器节点配置"""
        if 'executor' not in self.config:
            raise ConfigValidationError("执行器模式需要executor配置节")
        
        executor_config = self.config['executor']
        
        # 验证中央服务器地址
        central_server = executor_config.get('central_server')
        if not central_server:
            raise ConfigValidationError("执行器节点必须配置central_server")
    
    def _validate_web_config(self) -> None:
        """验证Web界面配置"""
        if 'web' not in self.config:
            raise ConfigValidationError("Web模式需要web配置节")
        
        web_config = self.config['web']
        
        # 验证端口
        port = web_config.get('port', 8080)
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ConfigValidationError(f"无效的Web端口: {port}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值
        
        Args:
            key: 配置键，支持点分隔的嵌套键（如 'system.mode'）
            default: 默认值
            
        Returns:
            配置值
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """设置配置值
        
        Args:
            key: 配置键，支持点分隔的嵌套键
            value: 配置值
        """
        keys = key.split('.')
        config = self.config
        
        # 创建嵌套字典
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            elif not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def update(self, updates: Dict[str, Any]) -> None:
        """批量更新配置
        
        Args:
            updates: 更新的配置字典
        """
        def deep_update(base: Dict[str, Any], updates: Dict[str, Any]) -> None:
            for key, value in updates.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    deep_update(base[key], value)
                else:
                    base[key] = value
        
        deep_update(self.config, updates)
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """获取配置节
        
        Args:
            section: 配置节名称
            
        Returns:
            配置节字典
        """
        return self.config.get(section, {})
    
    def has_section(self, section: str) -> bool:
        """检查是否存在配置节
        
        Args:
            section: 配置节名称
            
        Returns:
            是否存在
        """
        return section in self.config
    
    def get_config_info(self) -> Dict[str, Any]:
        """获取配置文件信息
        
        Returns:
            配置文件信息
        """
        try:
            stat = self.config_path.stat()
            return {
                'path': str(self.config_path),
                'exists': True,
                'size_bytes': stat.st_size,
                'modified_time': datetime.fromtimestamp(stat.st_mtime),
                'is_readable': os.access(self.config_path, os.R_OK),
                'is_writable': os.access(self.config_path, os.W_OK),
                'format': self.config_path.suffix.lower()
            }
        except Exception as e:
            return {
                'path': str(self.config_path),
                'exists': False,
                'error': str(e)
            }
    
    def _get_config_schema(self) -> Dict[str, Any]:
        """获取配置模式定义
        
        Returns:
            配置模式字典
        """
        return {
            'required_sections': ['system', 'logging'],
            'optional_sections': ['central', 'agent', 'executor', 'web', 'security', 'analysis'],
            'system': {
                'required_fields': ['mode', 'node_id'],
                'optional_fields': ['debug', 'max_workers']
            },
            'logging': {
                'required_fields': [],
                'optional_fields': ['level', 'file', 'max_size', 'backup_count', 'console']
            }
        }


def load_config(config_path: str) -> Dict[str, Any]:
    """简单的配置加载函数
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        配置字典
        
    Raises:
        ConfigLoadError: 加载失败
    """
    manager = ConfigManager(config_path)
    return manager.config


def validate_config_file(config_path: str) -> bool:
    """验证配置文件
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        是否有效
    """
    try:
        ConfigManager(config_path)
        return True
    except (ConfigError, Exception):
        return False


def create_default_config(config_path: str, mode: str = 'all') -> None:
    """创建默认配置文件
    
    Args:
        config_path: 配置文件路径
        mode: 运行模式
        
    Raises:
        ConfigSaveError: 保存失败
    """
    default_config = {
        'system': {
            'mode': mode,
            'node_id': f'node-{datetime.now().strftime("%Y%m%d%H%M%S")}',
            'debug': False,
            'max_workers': 4
        },
        'logging': {
            'level': 'INFO',
            'file': '/var/log/fail2ban-distributed/system.log',
            'max_size': '10MB',
            'backup_count': 5,
            'console': True
        },
        'security': {
            'api_key': '',
            'whitelist_ips': ['127.0.0.1', '::1'],
            'rate_limit': {
                'enabled': True,
                'requests_per_minute': 60
            }
        }
    }
    
    # 根据模式添加特定配置
    if mode in ['central', 'all']:
        default_config['central'] = {
            'host': '0.0.0.0',
            'port': 5000,
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
        }
    
    if mode in ['agent', 'all']:
        default_config['agent'] = {
            'central_server': 'http://localhost:5000',
            'nginx': {
                'access_log': '/var/log/nginx/access.log',
                'log_format': 'combined'
            },
            'report_interval': 30
        }
    
    if mode in ['executor', 'all']:
        default_config['executor'] = {
            'central_server': 'http://localhost:5000',
            'fail2ban_config': '/etc/fail2ban',
            'jail_name': 'nginx-distributed'
        }
    
    if mode in ['web', 'all']:
        default_config['web'] = {
            'host': '0.0.0.0',
            'port': 8080,
            'api_server': 'http://localhost:5000'
        }
    
    # 保存配置
    manager = ConfigManager.__new__(ConfigManager)
    manager.config_path = Path(config_path)
    manager.config = default_config
    manager.save_config(backup=False)


if __name__ == '__main__':
    # 测试配置管理器
    try:
        # 创建测试配置
        test_config_path = '/tmp/test_config.yaml'
        create_default_config(test_config_path, 'central')
        print(f"创建默认配置: {test_config_path}")
        
        # 加载和验证配置
        manager = ConfigManager(test_config_path)
        print(f"配置加载成功，模式: {manager.get('system.mode')}")
        
        # 测试配置更新
        manager.set('system.debug', True)
        manager.update({
            'logging': {
                'level': 'DEBUG'
            }
        })
        
        # 保存配置
        manager.save_config()
        print("配置更新和保存成功")
        
        # 获取配置信息
        info = manager.get_config_info()
        print(f"配置文件信息: {info}")
        
        print("配置管理器测试完成")
        
    except Exception as e:
        print(f"测试失败: {e}")