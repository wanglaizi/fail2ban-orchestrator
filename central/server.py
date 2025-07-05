#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 中央控制节点服务器
负责接收日志数据、分析攻击模式、下发封禁指令
"""

import asyncio
import json
import logging
import time
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import aiohttp
import yaml
from aiohttp import web, WSMsgType

from utils.logger import setup_logger
from utils.security import verify_api_key
from utils.database import DatabaseManager, hash_ip, DatabaseError, ConnectionError as DBConnectionError
from utils.config import ConfigManager
from analysis.pattern_detector import PatternDetector
from analysis.ip_analyzer import IPAnalyzer


class CentralServerError(Exception):
    """中央服务器异常"""
    pass


class LogProcessingError(CentralServerError):
    """日志处理异常"""
    pass


class BanOperationError(CentralServerError):
    """封禁操作异常"""
    pass


class CentralServer:
    """中央控制节点服务器"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        # 配置管理
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load_config()
        self.logger = setup_logger("central", self.config)
        
        # 数据库管理器
        self.db_manager: Optional[DatabaseManager] = None
        
        # 分析引擎
        self.pattern_detector = PatternDetector(self.config)
        self.ip_analyzer = IPAnalyzer(self.config)
        
        # WebSocket连接管理
        self.websocket_connections: Dict[str, web.WebSocketResponse] = {}
        
        # 执行节点管理
        self.executor_nodes: Dict[str, Dict[str, Any]] = {}
        
        # 性能统计
        self.stats = {
            'logs_processed': 0,
            'bans_initiated': 0,
            'errors_count': 0,
            'start_time': time.time()
        }
        
        # 应用实例
        self.app = web.Application()
        self._setup_routes()
    
    async def _reload_config(self) -> None:
        """重新加载配置"""
        try:
            self.config = self.config_manager.load_config()
            self.logger.info("配置重新加载成功")
        except Exception as e:
            self.logger.error(f"配置重新加载失败: {e}")
            raise CentralServerError(f"配置重新加载失败: {e}")
    
    def _setup_routes(self):
        """设置路由"""
        # API路由
        self.app.router.add_post('/api/logs/submit', self.handle_log_submission)
        self.app.router.add_post('/api/executor/register', self.handle_executor_register)
        self.app.router.add_get('/api/status', self.handle_status)
        self.app.router.add_get('/api/stats', self.handle_stats)
        
        # WebSocket路由
        self.app.router.add_get('/ws', self.handle_websocket)
        
        # 中间件
        self.app.middlewares.append(self.auth_middleware)
        self.app.middlewares.append(self.cors_middleware)
    
    async def auth_middleware(self, request, handler):
        """API认证中间件"""
        if request.path.startswith('/api/'):
            api_key = request.headers.get('X-API-Key')
            if not verify_api_key(api_key, self.config['central']['api']['api_key']):
                return web.json_response({'error': 'Invalid API key'}, status=401)
        
        return await handler(request)
    
    async def cors_middleware(self, request, handler):
        """CORS中间件"""
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
        return response
    
    async def init_databases(self) -> None:
        """初始化数据库连接"""
        try:
            self.db_manager = DatabaseManager(self.config)
            await self.db_manager.initialize()
            
            # 创建必要的索引
            await self._create_indexes()
            
            self.logger.info("数据库连接初始化成功")
            
        except Exception as e:
            self.logger.error(f"数据库连接初始化失败: {e}")
            raise CentralServerError(f"数据库初始化失败: {e}")
    
    async def _create_indexes(self) -> None:
        """创建数据库索引"""
        try:
            mongo_manager = self.db_manager.get_mongo()
            if mongo_manager:
                # 为access_logs集合创建索引
                await mongo_manager.create_indexes('access_logs', [
                    ([('remote_addr', 1), ('timestamp', -1)], {'background': True}),
                    ([('processed_at', -1)], {'background': True}),
                    ([('node_id', 1)], {'background': True})
                ])
                
                # 为ban_records集合创建索引
                await mongo_manager.create_indexes('ban_records', [
                    ([('ip', 1), ('timestamp', -1)], {'background': True}),
                    ([('status', 1)], {'background': True}),
                    ([('timestamp', -1)], {'background': True})
                ])
                
                self.logger.info("数据库索引创建完成")
        except Exception as e:
            self.logger.warning(f"索引创建失败: {e}")
    
    async def handle_log_submission(self, request):
        """处理日志提交"""
        try:
            data = await request.json()
            node_id = data.get('node_id')
            logs = data.get('logs', [])
            
            self.logger.info(f"收到来自节点 {node_id} 的 {len(logs)} 条日志")
            
            # 处理每条日志
            for log_entry in logs:
                await self._process_log_entry(log_entry, node_id)
            
            return web.json_response({
                'status': 'success',
                'processed': len(logs),
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            self.logger.error(f"日志处理失败: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _process_log_entry(self, log_entry: dict, node_id: str):
        """处理单条日志记录"""
        try:
            # 提取关键信息
            ip = log_entry.get('remote_addr')
            user_agent = log_entry.get('http_user_agent', '')
            request_uri = log_entry.get('request_uri', '')
            status = log_entry.get('status')
            timestamp = log_entry.get('timestamp')
            
            if not ip:
                return
            
            # 检查白名单
            if self._is_whitelisted(ip):
                return
            
            # 存储到Redis（用于实时分析）
            await self._store_to_redis(ip, log_entry)
            
            # 存储到MongoDB（用于历史分析）
            await self._store_to_mongodb(log_entry, node_id)
            
            # 模式检测
            attack_detected = await self.pattern_detector.detect(log_entry)
            
            # IP行为分析
            ip_analysis = await self.ip_analyzer.analyze(ip)
            
            # 判断是否需要封禁
            if attack_detected or ip_analysis.get('should_ban', False):
                await self._initiate_ban(ip, {
                    'reason': attack_detected or ip_analysis.get('reason'),
                    'node_id': node_id,
                    'log_entry': log_entry
                })
            
        except Exception as e:
            self.logger.error(f"日志条目处理失败: {e}")
    
    def _is_whitelisted(self, ip: str) -> bool:
        """检查IP是否在白名单中"""
        whitelist = self.config.get('whitelist', {})
        
        # 检查IP白名单
        if ip in whitelist.get('ips', []):
            return True
        
        # 检查网段白名单
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in whitelist.get('networks', []):
                if ip_obj in ipaddress.ip_network(network):
                    return True
        except ValueError:
            pass
        
        return False
    
    async def _store_to_redis(self, ip: str, log_entry: dict):
        """存储日志到Redis"""
        try:
            # 使用哈希存储IP统计信息
            ip_key = f"ip:{hash_ip(ip)}"
            
            # 增加请求计数
            await self.redis.hincrby(ip_key, 'request_count', 1)
            
            # 记录最后访问时间
            await self.redis.hset(ip_key, 'last_seen', time.time())
            
            # 设置过期时间（24小时）
            await self.redis.expire(ip_key, 86400)
            
            # 如果是错误状态码，增加错误计数
            if log_entry.get('status', 200) >= 400:
                await self.redis.hincrby(ip_key, 'error_count', 1)
            
        except Exception as e:
            self.logger.error(f"Redis存储失败: {e}")
    
    async def _store_to_mongodb(self, log_entry: dict, node_id: str):
        """存储日志到MongoDB"""
        try:
            db = self.mongodb[self.config['central']['database']['mongodb']['database']]
            collection = db.access_logs
            
            # 添加元数据
            log_entry['node_id'] = node_id
            log_entry['processed_at'] = datetime.now()
            
            await collection.insert_one(log_entry)
            
        except Exception as e:
            self.logger.error(f"MongoDB存储失败: {e}")
    
    async def _initiate_ban(self, ip: str, ban_info: dict):
        """发起IP封禁"""
        try:
            ban_record = {
                'ip': ip,
                'reason': ban_info['reason'],
                'source_node': ban_info['node_id'],
                'timestamp': datetime.now(),
                'duration': self.config['analysis']['ban_rules']['ban_duration'],
                'status': 'pending'
            }
            
            # 存储封禁记录
            db = self.mongodb[self.config['central']['database']['mongodb']['database']]
            await db.ban_records.insert_one(ban_record)
            
            # 通知所有执行节点
            await self._notify_executors({
                'action': 'ban',
                'ip': ip,
                'duration': ban_record['duration'],
                'reason': ban_record['reason']
            })
            
            self.logger.warning(f"发起IP封禁: {ip}, 原因: {ban_info['reason']}")
            
        except Exception as e:
            self.logger.error(f"封禁发起失败: {e}")
    
    async def _notify_executors(self, message: dict):
        """通知执行节点"""
        # 通过WebSocket通知在线的执行节点
        for node_id, ws in self.websocket_connections.items():
            try:
                await ws.send_str(json.dumps(message))
            except Exception as e:
                self.logger.error(f"通知执行节点 {node_id} 失败: {e}")
    
    async def handle_executor_register(self, request):
        """处理执行节点注册"""
        try:
            data = await request.json()
            node_id = data.get('node_id')
            node_info = data.get('node_info', {})
            
            self.executor_nodes[node_id] = {
                'info': node_info,
                'registered_at': datetime.now(),
                'last_heartbeat': datetime.now()
            }
            
            self.logger.info(f"执行节点注册: {node_id}")
            
            return web.json_response({
                'status': 'registered',
                'node_id': node_id
            })
            
        except Exception as e:
            self.logger.error(f"执行节点注册失败: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def handle_websocket(self, request):
        """处理WebSocket连接"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        node_id = None
        
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    
                    if data.get('type') == 'register':
                        node_id = data.get('node_id')
                        self.websocket_connections[node_id] = ws
                        await ws.send_str(json.dumps({
                            'type': 'registered',
                            'node_id': node_id
                        }))
                        self.logger.info(f"WebSocket连接注册: {node_id}")
                    
                    elif data.get('type') == 'heartbeat':
                        if node_id and node_id in self.executor_nodes:
                            self.executor_nodes[node_id]['last_heartbeat'] = datetime.now()
                        await ws.send_str(json.dumps({'type': 'pong'}))
                    
                except Exception as e:
                    self.logger.error(f"WebSocket消息处理失败: {e}")
            
            elif msg.type == WSMsgType.ERROR:
                self.logger.error(f"WebSocket错误: {ws.exception()}")
        
        # 清理连接
        if node_id and node_id in self.websocket_connections:
            del self.websocket_connections[node_id]
            self.logger.info(f"WebSocket连接断开: {node_id}")
        
        return ws
    
    async def handle_status(self, request):
        """处理状态查询"""
        return web.json_response({
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'connected_executors': len(self.websocket_connections),
            'registered_nodes': len(self.executor_nodes)
        })
    
    async def handle_stats(self, request):
        """处理统计信息查询"""
        try:
            # 从MongoDB获取统计信息
            db = self.mongodb[self.config['central']['database']['mongodb']['database']]
            
            # 今日日志统计
            today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today_logs = await db.access_logs.count_documents({
                'processed_at': {'$gte': today}
            })
            
            # 今日封禁统计
            today_bans = await db.ban_records.count_documents({
                'timestamp': {'$gte': today}
            })
            
            return web.json_response({
                'today_logs': today_logs,
                'today_bans': today_bans,
                'active_connections': len(self.websocket_connections),
                'registered_executors': len(self.executor_nodes)
            })
            
        except Exception as e:
            self.logger.error(f"统计信息查询失败: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def start(self):
        """启动服务器"""
        try:
            # 初始化数据库
            await self.init_databases()
            
            # 启动HTTP服务器
            runner = web.AppRunner(self.app)
            await runner.setup()
            
            site = web.TCPSite(
                runner,
                self.config['central']['api']['host'],
                self.config['central']['api']['port']
            )
            await site.start()
            
            self.logger.info(
                f"中央控制节点启动成功，监听 "
                f"{self.config['central']['api']['host']}:"
                f"{self.config['central']['api']['port']}"
            )
            
            # 保持运行
            while True:
                await asyncio.sleep(1)
                
        except Exception as e:
            self.logger.error(f"服务器启动失败: {e}")
            raise


if __name__ == '__main__':
    import sys
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"
    
    server = CentralServer(config_path)
    
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        print(f"服务器运行错误: {e}")
        sys.exit(1)