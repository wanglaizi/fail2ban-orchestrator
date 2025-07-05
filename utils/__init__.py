#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 工具模块

提供系统所需的各种工具和实用函数。
"""

__version__ = "1.0.0"
__author__ = "Fail2ban开发团队"

# 导出主要的工具类和函数
try:
    from .config import ConfigManager
    from .logger import setup_logger
    from .security import generate_api_key
    from .database import DatabaseManager
    
    __all__ = [
        'ConfigManager',
        'setup_logger', 
        'generate_api_key',
        'DatabaseManager'
    ]
except ImportError as e:
    # 如果某些模块不存在，只导出可用的
    __all__ = []
    print(f"警告: 部分工具模块导入失败: {e}")