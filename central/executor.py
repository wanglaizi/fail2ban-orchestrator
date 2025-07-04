#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 封禁执行节点
负责接收中央控制节点的封禁指令，通过fail2ban执行IP封禁
"""

import asyncio
import json
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import aiohttp
import yaml
from aiohttp import WSMsgType

from utils.logger import setup_logger
from utils.fail2ban_manager import Fail2banManager


class ExecutorNode:
    """封禁执行节点"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self._load_config(config_path)
        self.logger = setup_logger("executor", self.config)
        
        # 配置信息
        self.node_id = self.config['system']['node_id']
        self.central_server = self.config['executor']['central_server']
        
        # Fail2ban管理器
        self.fail2ban_manager = Fail2banManager(self.config)
        
        # 状态管理
        self.running = False
        self.websocket: Optional[aiohttp.ClientWebSocketResponse] = None
        self.session: Optional[aiohttp.ClientSession] = None
        
        # 封禁记录
        self.active_bans: Dict[str, Dict] = {}
        
        # 心跳间隔
        self.heartbeat_interval = 30
    
    def _load_config(self, config_path: str) -> dict:
        """加载配置文件"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"配置文件加载失败: {e}")
            raise
    
    async def init_session(self):
        """初始化HTTP会话"""
        headers = {
            'X-API-Key': self.central_server['api_key'],
            'Content-Type': 'application/json'
        }
        
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=timeout
        )
    
    async def register_with_central(self):
        """向中央服务器注册"""
        try:
            url = f"http://{self.central_server['host']}:{self.central_server['port']}/api/executor/register"
            
            # 获取节点信息
            node_info = await self._get_node_info()
            
            payload = {
                'node_id': self.node_id,
                'node_info': node_info
            }
            
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    self.logger.info(f"成功注册到中央服务器: {result}")
                    return True
                else:
                    error_text = await response.text()
                    self.logger.error(f"注册失败，状态码: {response.status}, 响应: {error_text}")
                    return False
        
        except Exception as e:
            self.logger.error(f"注册异常: {e}")
            return False
    
    async def _get_node_info(self) -> dict:
        """获取节点信息"""
        try:
            # 获取系统信息
            import platform
            import psutil
            
            # 获取fail2ban版本
            fail2ban_version = "unknown"
            try:
                result = subprocess.run(
                    ['fail2ban-client', 'version'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    fail2ban_version = result.stdout.strip()
            except Exception:
                pass
            
            return {
                'hostname': platform.node(),
                'os': f"{platform.system()} {platform.release()}",
                'python_version': platform.python_version(),
                'fail2ban_version': fail2ban_version,
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'started_at': datetime.now().isoformat()
            }
        
        except Exception as e:
            self.logger.error(f"获取节点信息失败: {e}")
            return {'error': str(e)}
    
    async def connect_websocket(self):
        """连接WebSocket"""
        max_retries = 5
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                ws_url = f"ws://{self.central_server['host']}:{self.central_server['port']}/ws"
                
                self.websocket = await self.session.ws_connect(ws_url)
                
                # 发送注册消息
                register_msg = {
                    'type': 'register',
                    'node_id': self.node_id
                }
                await self.websocket.send_str(json.dumps(register_msg))
                
                self.logger.info("WebSocket连接建立成功")
                return True
            
            except Exception as e:
                self.logger.error(f"WebSocket连接失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # 指数退避
        
        return False
    
    async def handle_websocket_messages(self):
        """处理WebSocket消息"""
        try:
            async for msg in self.websocket:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._process_message(data)
                    except Exception as e:
                        self.logger.error(f"消息处理失败: {e}")
                
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f"WebSocket错误: {self.websocket.exception()}")
                    break
                
                elif msg.type == WSMsgType.CLOSE:
                    self.logger.warning("WebSocket连接关闭")
                    break
        
        except Exception as e:
            self.logger.error(f"WebSocket消息处理异常: {e}")
    
    async def _process_message(self, data: dict):
        """处理接收到的消息"""
        msg_type = data.get('type')
        
        if msg_type == 'registered':
            self.logger.info(f"WebSocket注册成功: {data.get('node_id')}")
        
        elif data.get('action') == 'ban':
            await self._handle_ban_request(data)
        
        elif data.get('action') == 'unban':
            await self._handle_unban_request(data)
        
        elif msg_type == 'pong':
            self.logger.debug("收到心跳响应")
        
        else:
            self.logger.warning(f"未知消息类型: {data}")
    
    async def _handle_ban_request(self, data: dict):
        """处理封禁请求"""
        try:
            ip = data.get('ip')
            duration = data.get('duration', 60)  # 默认60分钟
            reason = data.get('reason', 'Distributed ban')
            
            if not ip:
                self.logger.error("封禁请求缺少IP地址")
                return
            
            self.logger.info(f"执行IP封禁: {ip}, 时长: {duration}分钟, 原因: {reason}")
            
            # 执行封禁
            success = await self.fail2ban_manager.ban_ip(ip, duration, reason)
            
            if success:
                # 记录封禁信息
                self.active_bans[ip] = {
                    'banned_at': datetime.now(),
                    'duration': duration,
                    'reason': reason,
                    'expires_at': datetime.now() + timedelta(minutes=duration)
                }
                
                self.logger.info(f"IP {ip} 封禁成功")
            else:
                self.logger.error(f"IP {ip} 封禁失败")
        
        except Exception as e:
            self.logger.error(f"处理封禁请求失败: {e}")
    
    async def _handle_unban_request(self, data: dict):
        """处理解封请求"""
        try:
            ip = data.get('ip')
            
            if not ip:
                self.logger.error("解封请求缺少IP地址")
                return
            
            self.logger.info(f"执行IP解封: {ip}")
            
            # 执行解封
            success = await self.fail2ban_manager.unban_ip(ip)
            
            if success:
                # 移除封禁记录
                self.active_bans.pop(ip, None)
                self.logger.info(f"IP {ip} 解封成功")
            else:
                self.logger.error(f"IP {ip} 解封失败")
        
        except Exception as e:
            self.logger.error(f"处理解封请求失败: {e}")
    
    async def send_heartbeat(self):
        """发送心跳"""
        while self.running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                if self.websocket and not self.websocket.closed:
                    heartbeat_msg = {
                        'type': 'heartbeat',
                        'node_id': self.node_id,
                        'timestamp': datetime.now().isoformat(),
                        'active_bans': len(self.active_bans)
                    }
                    
                    await self.websocket.send_str(json.dumps(heartbeat_msg))
                    self.logger.debug("发送心跳")
            
            except Exception as e:
                self.logger.error(f"发送心跳失败: {e}")
    
    async def cleanup_expired_bans(self):
        """清理过期的封禁"""
        while self.running:
            try:
                await asyncio.sleep(300)  # 每5分钟检查一次
                
                now = datetime.now()
                expired_ips = []
                
                for ip, ban_info in self.active_bans.items():
                    if now >= ban_info['expires_at']:
                        expired_ips.append(ip)
                
                for ip in expired_ips:
                    self.logger.info(f"封禁过期，自动解封: {ip}")
                    success = await self.fail2ban_manager.unban_ip(ip)
                    
                    if success:
                        self.active_bans.pop(ip, None)
                    else:
                        self.logger.error(f"自动解封失败: {ip}")
            
            except Exception as e:
                self.logger.error(f"清理过期封禁失败: {e}")
    
    async def monitor_fail2ban_status(self):
        """监控fail2ban状态"""
        while self.running:
            try:
                await asyncio.sleep(60)  # 每分钟检查一次
                
                # 检查fail2ban服务状态
                is_running = await self.fail2ban_manager.is_service_running()
                
                if not is_running:
                    self.logger.error("Fail2ban服务未运行")
                    # 可以尝试启动服务或发送告警
                else:
                    self.logger.debug("Fail2ban服务运行正常")
            
            except Exception as e:
                self.logger.error(f"监控fail2ban状态失败: {e}")
    
    async def reconnect_websocket(self):
        """重连WebSocket"""
        while self.running:
            try:
                if not self.websocket or self.websocket.closed:
                    self.logger.info("尝试重连WebSocket...")
                    
                    if await self.connect_websocket():
                        # 重新启动消息处理
                        asyncio.create_task(self.handle_websocket_messages())
                    else:
                        self.logger.error("WebSocket重连失败")
                
                await asyncio.sleep(30)  # 每30秒检查一次连接状态
            
            except Exception as e:
                self.logger.error(f"WebSocket重连异常: {e}")
    
    async def start(self):
        """启动执行节点"""
        try:
            self.logger.info(f"启动封禁执行节点，节点ID: {self.node_id}")
            
            # 初始化fail2ban管理器
            await self.fail2ban_manager.initialize()
            
            # 初始化HTTP会话
            await self.init_session()
            
            # 注册到中央服务器
            if not await self.register_with_central():
                raise Exception("注册到中央服务器失败")
            
            # 连接WebSocket
            if not await self.connect_websocket():
                raise Exception("WebSocket连接失败")
            
            # 设置运行状态
            self.running = True
            
            # 启动后台任务
            tasks = [
                asyncio.create_task(self.handle_websocket_messages()),
                asyncio.create_task(self.send_heartbeat()),
                asyncio.create_task(self.cleanup_expired_bans()),
                asyncio.create_task(self.monitor_fail2ban_status()),
                asyncio.create_task(self.reconnect_websocket())
            ]
            
            self.logger.info("封禁执行节点启动成功")
            
            # 等待任务完成
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except Exception as e:
            self.logger.error(f"执行节点启动失败: {e}")
            raise
    
    async def stop(self):
        """停止执行节点"""
        self.logger.info("正在停止封禁执行节点...")
        
        self.running = False
        
        # 关闭WebSocket连接
        if self.websocket and not self.websocket.closed:
            await self.websocket.close()
        
        # 关闭HTTP会话
        if self.session:
            await self.session.close()
        
        # 清理资源
        await self.fail2ban_manager.cleanup()
        
        self.logger.info("封禁执行节点已停止")


if __name__ == '__main__':
    import sys
    import signal
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"
    
    executor = ExecutorNode(config_path)
    
    # 信号处理
    def signal_handler(signum, frame):
        print("\n收到停止信号，正在关闭执行节点...")
        asyncio.create_task(executor.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        asyncio.run(executor.start())
    except KeyboardInterrupt:
        print("\n执行节点已停止")
    except Exception as e:
        print(f"执行节点运行错误: {e}")
        sys.exit(1)