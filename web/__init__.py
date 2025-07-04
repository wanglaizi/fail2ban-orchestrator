#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - Web模块
"""

from .dashboard import DashboardApp, create_app

__all__ = ['DashboardApp', 'create_app']