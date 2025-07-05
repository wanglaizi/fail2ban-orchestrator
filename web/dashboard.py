#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - Web仪表板

提供Web界面用于监控和管理分布式Fail2ban系统
包含实时统计、封禁管理、节点状态等功能
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Union

from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import logging

from utils.security import verify_api_key
from utils.logger import setup_logger


# 自定义异常类
class DashboardError(Exception):
    """仪表板基础异常"""
    pass


class WebSocketError(DashboardError):
    """WebSocket连接异常"""
    pass


class APIError(DashboardError):
    """API调用异常"""
    pass


# 数据模型
class BanRequest(BaseModel):
    """封禁请求模型"""
    ip: str = Field(..., description="要封禁的IP地址", regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    reason: str = Field(..., description="封禁原因", min_length=1, max_length=200)
    duration: int = Field(3600, description="封禁时长(秒)", ge=60, le=86400*30)  # 1分钟到30天
    node_id: Optional[str] = Field(None, description="执行封禁的节点ID")


class UnbanRequest(BaseModel):
    """解封请求模型"""
    ip: str = Field(..., description="要解封的IP地址", regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    reason: str = Field("手动解封", description="解封原因", max_length=200)
    node_id: Optional[str] = Field(None, description="执行解封的节点ID")


class SystemStats(BaseModel):
    """系统统计模型"""
    total_requests: int = Field(..., description="总请求数", ge=0)
    total_attacks: int = Field(..., description="总攻击数", ge=0)
    banned_ips: int = Field(..., description="封禁IP数量", ge=0)
    active_nodes: int = Field(..., description="活跃节点数", ge=0)
    uptime: str = Field(..., description="系统运行时间")


class IPInfo(BaseModel):
    """IP信息模型"""
    ip: str = Field(..., description="IP地址")
    risk_score: float = Field(..., description="风险评分", ge=0.0, le=100.0)
    attack_count: int = Field(..., description="攻击次数", ge=0)
    last_seen: str = Field(..., description="最后出现时间")
    status: str = Field(..., description="状态")
    geo_info: Optional[Dict[str, Any]] = Field(None, description="地理信息")


class DashboardApp:
    """Web仪表板应用"""
    
    def __init__(self, config: Dict[str, Any]) -> None:
        """初始化仪表板应用
        
        Args:
            config: 配置字典
            
        Raises:
            DashboardError: 配置错误或初始化失败
        """
        try:
            self.config: Dict[str, Any] = config
            self.web_config: Dict[str, Any] = config.get('web', {})
            self.api_key: str = config.get('central', {}).get('api', {}).get('api_key', '')
            
            # 设置日志
            self.logger = setup_logger('dashboard', 'INFO')
            
            # 验证配置
            self._validate_config()
            
            # 创建FastAPI应用
            self.app: FastAPI = FastAPI(
                title="分布式Fail2ban系统",
                description="Web管理界面",
                version="1.0.0"
            )
            
            # WebSocket连接管理
            self.websocket_connections: Set[WebSocket] = set()
            
            # 设置中间件
            self._setup_middleware()
            
            # 设置路由
            self._setup_routes()
            
        except Exception as e:
            self.logger.error(f"初始化仪表板应用失败: {e}")
            raise DashboardError(f"初始化失败: {e}") from e
        
        # 模拟数据存储（实际应用中应该连接到Redis/MongoDB）
        self.mock_data = {
            'system_stats': {
                'total_requests': 125430,
                'total_attacks': 1247,
                'banned_ips': 89,
                'active_nodes': 3,
                'uptime': '2天 14小时 32分钟'
            },
            'banned_ips': [
                {
                    'ip': '192.168.1.100',
                    'reason': 'SQL注入攻击',
                    'banned_at': '2024-01-15 10:30:00',
                    'expires_at': '2024-01-15 11:30:00',
                    'node_id': 'node-001'
                },
                {
                    'ip': '10.0.0.50',
                    'reason': 'XSS攻击',
                    'banned_at': '2024-01-15 09:15:00',
                    'expires_at': '2024-01-15 10:15:00',
                    'node_id': 'node-002'
                }
            ],
            'recent_attacks': [
                {
                    'timestamp': '2024-01-15 10:35:00',
                    'ip': '203.0.113.1',
                    'type': 'SQL注入',
                    'path': '/login.php?id=1 union select',
                    'status': 'blocked'
                },
                {
                    'timestamp': '2024-01-15 10:32:00',
                    'ip': '198.51.100.1',
                    'type': 'XSS攻击',
                    'path': '/search?q=<script>alert(1)</script>',
                    'status': 'blocked'
                }
            ],
            'nodes': [
                {
                    'node_id': 'node-001',
                    'hostname': 'web-server-01',
                    'region': 'Beijing',
                    'status': 'online',
                    'last_heartbeat': '2024-01-15 10:35:30',
                    'banned_count': 45
                },
                {
                    'node_id': 'node-002',
                    'hostname': 'web-server-02',
                    'region': 'Shanghai',
                    'status': 'online',
                    'last_heartbeat': '2024-01-15 10:35:25',
                    'banned_count': 32
                },
                {
                    'node_id': 'node-003',
                    'hostname': 'web-server-03',
                    'region': 'Guangzhou',
                    'status': 'offline',
                    'last_heartbeat': '2024-01-15 10:30:00',
                    'banned_count': 12
                }
            ]
        }
    
    def _validate_config(self) -> None:
        """验证配置参数
        
        Raises:
            DashboardError: 配置验证失败
        """
        if not self.api_key:
            raise DashboardError("API密钥未配置")
        
        # 验证Web配置
        host = self.web_config.get('host', '0.0.0.0')
        port = self.web_config.get('port', 8080)
        
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise DashboardError(f"无效的端口号: {port}")
        
        self.logger.info(f"配置验证通过 - Host: {host}, Port: {port}")
    
    def _setup_middleware(self) -> None:
        """设置中间件
        
        Raises:
            DashboardError: 中间件设置失败
        """
        try:
            # CORS中间件
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            
            # 请求日志中间件
            @self.app.middleware("http")
            async def log_requests(request: Request, call_next) -> Any:
                start_time = time.time()
                try:
                    response = await call_next(request)
                    process_time = time.time() - start_time
                    
                    self.logger.info(
                        f"{request.method} {request.url.path} - "
                        f"{response.status_code} - {process_time:.3f}s"
                    )
                    
                    return response
                except Exception as e:
                    process_time = time.time() - start_time
                    self.logger.error(
                        f"{request.method} {request.url.path} - "
                        f"ERROR: {e} - {process_time:.3f}s"
                    )
                    raise
                    
        except Exception as e:
            self.logger.error(f"设置中间件失败: {e}")
            raise DashboardError(f"中间件设置失败: {e}") from e
    
    def _setup_routes(self) -> None:
        """设置路由
        
        Raises:
            DashboardError: 路由设置失败
        """
        try:
            # 静态文件
            # self.app.mount("/static", StaticFiles(directory="web/static"), name="static")
            
            # 模板
            # templates = Jinja2Templates(directory="web/templates")
            
            # 安全依赖
            security = HTTPBearer()
            
            def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
                if not verify_api_key(credentials.credentials, self.api_key):
                    raise HTTPException(status_code=401, detail="无效的API密钥")
                return credentials.credentials
            
            # 主页
            @self.app.get("/", response_class=HTMLResponse)
            async def dashboard_home(request: Request) -> HTMLResponse:
                """仪表板首页
                
                Args:
                    request: HTTP请求对象
                    
                Returns:
                    HTML响应
                    
                Raises:
                    HTTPException: 页面加载失败
                """
                try:
                    return HTMLResponse(content=self._get_dashboard_html())
                except Exception as e:
                    self.logger.error(f"获取仪表板页面失败: {e}")
                    raise HTTPException(status_code=500, detail="页面加载失败")
            
            # API路由
            @self.app.get("/api/stats")
            async def get_system_stats() -> Dict[str, Any]:
                """获取系统统计信息
                
                Returns:
                    系统统计数据字典
                    
                Raises:
                    HTTPException: 获取统计数据失败
                """
                try:
                    return self.mock_data['system_stats']
                except Exception as e:
                    self.logger.error(f"获取系统统计失败: {e}")
                    raise HTTPException(status_code=500, detail="获取统计数据失败")
            
            @self.app.get("/api/banned-ips")
            async def get_banned_ips() -> List[Dict[str, Any]]:
                """获取封禁IP列表
                
                Returns:
                    封禁IP列表
                    
                Raises:
                    HTTPException: 获取封禁列表失败
                """
                try:
                    return self.mock_data['banned_ips']
                except Exception as e:
                    self.logger.error(f"获取封禁IP列表失败: {e}")
                    raise HTTPException(status_code=500, detail="获取封禁列表失败")
            
            @self.app.get("/api/recent-attacks")
            async def get_recent_attacks() -> List[Dict[str, Any]]:
                """获取最近攻击记录
                
                Returns:
                    最近攻击记录列表
                    
                Raises:
                    HTTPException: 获取攻击记录失败
                """
                try:
                    return self.mock_data['recent_attacks']
                except Exception as e:
                    self.logger.error(f"获取攻击记录失败: {e}")
                    raise HTTPException(status_code=500, detail="获取攻击记录失败")
            
            @self.app.get("/api/nodes")
            async def get_nodes() -> List[Dict[str, Any]]:
                """获取节点状态
                
                Returns:
                    节点状态列表
                    
                Raises:
                    HTTPException: 获取节点状态失败
                """
                try:
                    return self.mock_data['nodes']
                except Exception as e:
                    self.logger.error(f"获取节点状态失败: {e}")
                    raise HTTPException(status_code=500, detail="获取节点状态失败")
            
            @self.app.post("/api/ban")
            async def ban_ip(request: BanRequest, token: str = Depends(verify_token)) -> Dict[str, str]:
                """手动封禁IP
                
                Args:
                    request: 封禁请求
                    token: API令牌
                    
                Returns:
                    操作结果
                    
                Raises:
                    HTTPException: 封禁操作失败
                """
                try:
                    # 检查IP是否已被封禁
                    if any(ban['ip'] == request.ip for ban in self.mock_data['banned_ips']):
                        raise HTTPException(status_code=400, detail=f"IP {request.ip} 已被封禁")
                    
                    # 创建封禁记录
                    ban_info = {
                        'ip': request.ip,
                        'reason': request.reason,
                        'banned_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'expires_at': (datetime.now() + timedelta(seconds=request.duration)).strftime('%Y-%m-%d %H:%M:%S'),
                        'node_id': request.node_id or 'manual',
                        'duration': request.duration
                    }
                    
                    self.mock_data['banned_ips'].append(ban_info)
                    
                    # 更新统计
                    self.mock_data['system_stats']['banned_ips'] = len(self.mock_data['banned_ips'])
                    
                    # 广播更新
                    await self._broadcast_update('ban', ban_info)
                    
                    self.logger.info(f"IP {request.ip} 已被封禁，原因: {request.reason}")
                    return {'status': 'success', 'message': f'IP {request.ip} 已被封禁'}
                    
                except HTTPException:
                    raise
                except Exception as e:
                    self.logger.error(f"封禁IP失败: {e}")
                    raise HTTPException(status_code=500, detail=f"封禁操作失败: {str(e)}")
            
            @self.app.post("/api/unban")
            async def unban_ip(request: UnbanRequest, token: str = Depends(verify_token)) -> Dict[str, str]:
                """手动解封IP
                
                Args:
                    request: 解封请求
                    token: API令牌
                    
                Returns:
                    操作结果
                    
                Raises:
                    HTTPException: 解封操作失败
                """
                try:
                    # 检查IP是否在封禁列表中
                    original_count = len(self.mock_data['banned_ips'])
                    
                    # 从封禁列表中移除
                    self.mock_data['banned_ips'] = [
                        ban for ban in self.mock_data['banned_ips']
                        if ban['ip'] != request.ip
                    ]
                    
                    # 检查是否实际移除了IP
                    if len(self.mock_data['banned_ips']) == original_count:
                        raise HTTPException(status_code=404, detail=f"IP {request.ip} 未在封禁列表中")
                    
                    unban_info = {
                        'ip': request.ip,
                        'reason': request.reason,
                        'unbanned_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    # 更新统计
                    self.mock_data['system_stats']['banned_ips'] = len(self.mock_data['banned_ips'])
                    
                    # 广播更新
                    await self._broadcast_update('unban', unban_info)
                    
                    self.logger.info(f"IP {request.ip} 已被解封，原因: {request.reason}")
                    return {'status': 'success', 'message': f'IP {request.ip} 已被解封'}
                    
                except HTTPException:
                    raise
                except Exception as e:
                    self.logger.error(f"解封IP失败: {e}")
                    raise HTTPException(status_code=500, detail=f"解封操作失败: {str(e)}")
            
            @self.app.get("/api/ip/{ip}")
            async def get_ip_info(ip: str) -> Dict[str, Any]:
                """获取IP详细信息
                
                Args:
                    ip: IP地址
                    
                Returns:
                    IP详细信息
                    
                Raises:
                    HTTPException: 获取IP信息失败
                """
                try:
                    # 验证IP格式
                    import re
                    if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                        raise HTTPException(status_code=400, detail="无效的IP地址格式")
                    
                    # 模拟IP信息
                    ip_info = {
                        'ip': ip,
                        'risk_score': 75.5,
                        'attack_count': 12,
                        'request_count': 156,
                        'last_seen': '2024-01-15 10:35:00',
                        'first_seen': '2024-01-15 08:20:00',
                        'status': 'banned' if any(ban['ip'] == ip for ban in self.mock_data['banned_ips']) else 'monitoring',
                        'geo_info': {
                            'country': 'CN',
                            'city': 'Beijing',
                            'isp': 'China Telecom'
                        },
                        'attack_types': ['SQL注入', 'XSS攻击'],
                        'user_agents': ['Mozilla/5.0', 'sqlmap/1.0'],
                        'paths': ['/login.php', '/admin/', '/wp-admin/']
                    }
                    
                    return ip_info
                    
                except HTTPException:
                    raise
                except Exception as e:
                    self.logger.error(f"获取IP信息失败: {e}")
                    raise HTTPException(status_code=500, detail="获取IP信息失败")
            
            @self.app.get("/api/charts/attacks")
            async def get_attack_charts() -> Dict[str, Any]:
                """获取攻击图表数据
                
                Returns:
                    攻击图表数据
                    
                Raises:
                    HTTPException: 获取图表数据失败
                """
                try:
                    # 模拟24小时攻击数据
                    hours: List[str] = []
                    attacks: List[int] = []
                    
                    for i in range(24):
                        hour = (datetime.now() - timedelta(hours=23-i)).strftime('%H:00')
                        hours.append(hour)
                        attacks.append(max(0, 50 + (i % 6) * 10 + (i % 3) * 5))
                    
                    return {
                        'labels': hours,
                        'datasets': [{
                            'label': '攻击次数',
                            'data': attacks,
                            'borderColor': 'rgb(255, 99, 132)',
                            'backgroundColor': 'rgba(255, 99, 132, 0.2)'
                        }]
                    }
                    
                except Exception as e:
                    self.logger.error(f"获取攻击图表数据失败: {e}")
                    raise HTTPException(status_code=500, detail="获取图表数据失败")
            
            @self.app.get("/api/charts/geo")
            async def get_geo_charts() -> Dict[str, List[Dict[str, Union[str, int]]]]:
                """获取地理分布图表数据
                
                Returns:
                    地理分布图表数据
                    
                Raises:
                    HTTPException: 获取地理数据失败
                """
                try:
                    return {
                        'countries': [
                            {'name': 'China', 'value': 45},
                            {'name': 'United States', 'value': 32},
                            {'name': 'Russia', 'value': 28},
                            {'name': 'Germany', 'value': 15},
                            {'name': 'Japan', 'value': 12}
                        ]
                    }
                    
                except Exception as e:
                    self.logger.error(f"获取地理图表数据失败: {e}")
                    raise HTTPException(status_code=500, detail="获取地理数据失败")
            
            # WebSocket端点
            @self.app.websocket("/ws")
            async def websocket_endpoint(websocket: WebSocket) -> None:
                await websocket.accept()
                self.websocket_connections.add(websocket)
                
                try:
                    while True:
                        # 发送实时数据
                        data = {
                            'type': 'stats_update',
                            'data': self.mock_data['system_stats'],
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        await websocket.send_text(json.dumps(data))
                        await asyncio.sleep(5)  # 每5秒发送一次更新
                
                except WebSocketDisconnect:
                    self.websocket_connections.remove(websocket)
                except Exception as e:
                    self.logger.error(f"WebSocket错误: {e}")
                    if websocket in self.websocket_connections:
                        self.websocket_connections.remove(websocket)
                     
        except Exception as e:
            self.logger.error(f"设置路由失败: {e}")
            raise DashboardError(f"路由设置失败: {e}") from e
    
    async def _broadcast_update(self, update_type: str, data: Dict[str, Any]) -> None:
        """广播更新到所有WebSocket连接
        
        Args:
            update_type: 更新类型
            data: 更新数据
            
        Raises:
            WebSocketError: WebSocket广播失败
        """
        if not self.websocket_connections:
            self.logger.debug("没有活跃的WebSocket连接")
            return
        
        try:
            message = {
                'type': update_type,
                'data': data,
                'timestamp': datetime.now().isoformat()
            }
            
            message_text = json.dumps(message, ensure_ascii=False)
            
            # 发送给所有连接的客户端
            disconnected: Set[WebSocket] = set()
            successful_sends = 0
            
            for websocket in self.websocket_connections:
                try:
                    await websocket.send_text(message_text)
                    successful_sends += 1
                except Exception as e:
                    self.logger.warning(f"WebSocket发送失败: {e}")
                    disconnected.add(websocket)
            
            # 移除断开的连接
            self.websocket_connections -= disconnected
            
            self.logger.debug(
                f"广播更新 {update_type}: 成功发送到 {successful_sends} 个连接, "
                f"移除 {len(disconnected)} 个断开连接"
            )
            
        except Exception as e:
            self.logger.error(f"广播更新失败: {e}")
            raise WebSocketError(f"广播失败: {e}") from e
    
    def _get_dashboard_html(self) -> str:
        """获取仪表板HTML页面
        
        Returns:
            HTML内容
        """
        return """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>分布式Fail2ban系统 - 管理面板</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 1.8rem;
            font-weight: 300;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }
        
        .content-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .card-header {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #e9ecef;
        }
        
        .card-header h2 {
            font-size: 1.2rem;
            color: #495057;
        }
        
        .card-body {
            padding: 1.5rem;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th,
        .table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        
        .table th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        .status {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .status.online {
            background-color: #d4edda;
            color: #155724;
        }
        
        .status.offline {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .status.banned {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background-color 0.2s;
        }
        
        .btn-primary {
            background-color: #007bff;
            color: white;
        }
        
        .btn-primary:hover {
            background-color: #0056b3;
        }
        
        .btn-danger {
            background-color: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background-color: #c82333;
        }
        
        .btn-success {
            background-color: #28a745;
            color: white;
        }
        
        .btn-success:hover {
            background-color: #1e7e34;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        .form-control {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 0.9rem;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 2rem;
            border-radius: 10px;
            width: 90%;
            max-width: 500px;
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: black;
        }
        
        .alert {
            padding: 0.75rem 1rem;
            margin-bottom: 1rem;
            border-radius: 4px;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        @media (max-width: 768px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ 分布式Fail2ban系统 - 管理面板</h1>
    </div>
    
    <div class="container">
        <!-- 统计卡片 -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>总请求数</h3>
                <div class="value" id="total-requests">-</div>
            </div>
            <div class="stat-card">
                <h3>攻击次数</h3>
                <div class="value" id="total-attacks">-</div>
            </div>
            <div class="stat-card">
                <h3>封禁IP数</h3>
                <div class="value" id="banned-ips">-</div>
            </div>
            <div class="stat-card">
                <h3>活跃节点</h3>
                <div class="value" id="active-nodes">-</div>
            </div>
        </div>
        
        <!-- 主要内容 -->
        <div class="content-grid">
            <!-- 攻击趋势图表 -->
            <div class="card">
                <div class="card-header">
                    <h2>📊 24小时攻击趋势</h2>
                </div>
                <div class="card-body">
                    <div class="chart-container">
                        <canvas id="attackChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- 节点状态 -->
            <div class="card">
                <div class="card-header">
                    <h2>🖥️ 节点状态</h2>
                </div>
                <div class="card-body">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>节点</th>
                                <th>状态</th>
                                <th>封禁数</th>
                            </tr>
                        </thead>
                        <tbody id="nodes-table">
                            <!-- 动态加载 -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- 封禁IP列表 -->
        <div class="card">
            <div class="card-header">
                <h2>🚫 封禁IP列表</h2>
                <button class="btn btn-primary" onclick="showBanModal()">手动封禁</button>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>IP地址</th>
                            <th>封禁原因</th>
                            <th>封禁时间</th>
                            <th>过期时间</th>
                            <th>节点</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="banned-ips-table">
                        <!-- 动态加载 -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- 最近攻击 -->
        <div class="card" style="margin-top: 2rem;">
            <div class="card-header">
                <h2>⚠️ 最近攻击记录</h2>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>时间</th>
                            <th>IP地址</th>
                            <th>攻击类型</th>
                            <th>攻击路径</th>
                            <th>状态</th>
                        </tr>
                    </thead>
                    <tbody id="attacks-table">
                        <!-- 动态加载 -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- 封禁IP模态框 -->
    <div id="banModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeBanModal()">&times;</span>
            <h2>手动封禁IP</h2>
            <form id="banForm">
                <div class="form-group">
                    <label for="banIp">IP地址:</label>
                    <input type="text" id="banIp" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="banReason">封禁原因:</label>
                    <input type="text" id="banReason" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="banDuration">封禁时长(秒):</label>
                    <input type="number" id="banDuration" class="form-control" value="3600" required>
                </div>
                <button type="submit" class="btn btn-danger">封禁</button>
                <button type="button" class="btn btn-secondary" onclick="closeBanModal()">取消</button>
            </form>
        </div>
    </div>
    
    <script>
        // 全局变量
        let attackChart;
        let ws;
        
        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboardData();
            initWebSocket();
            initChart();
            
            // 每30秒刷新一次数据
            setInterval(loadDashboardData, 30000);
        });
        
        // 加载仪表板数据
        async function loadDashboardData() {
            try {
                // 加载统计数据
                const stats = await axios.get('/api/stats');
                updateStats(stats.data);
                
                // 加载封禁IP
                const bannedIps = await axios.get('/api/banned-ips');
                updateBannedIpsTable(bannedIps.data);
                
                // 加载最近攻击
                const attacks = await axios.get('/api/recent-attacks');
                updateAttacksTable(attacks.data);
                
                // 加载节点状态
                const nodes = await axios.get('/api/nodes');
                updateNodesTable(nodes.data);
                
            } catch (error) {
                console.error('加载数据失败:', error);
            }
        }
        
        // 更新统计数据
        function updateStats(stats) {
            document.getElementById('total-requests').textContent = stats.total_requests.toLocaleString();
            document.getElementById('total-attacks').textContent = stats.total_attacks.toLocaleString();
            document.getElementById('banned-ips').textContent = stats.banned_ips;
            document.getElementById('active-nodes').textContent = stats.active_nodes;
        }
        
        // 更新封禁IP表格
        function updateBannedIpsTable(bannedIps) {
            const tbody = document.getElementById('banned-ips-table');
            tbody.innerHTML = '';
            
            bannedIps.forEach(ban => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${ban.ip}</td>
                    <td>${ban.reason}</td>
                    <td>${ban.banned_at}</td>
                    <td>${ban.expires_at}</td>
                    <td>${ban.node_id}</td>
                    <td>
                        <button class="btn btn-success btn-sm" onclick="unbanIp('${ban.ip}')">解封</button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }
        
        // 更新攻击记录表格
        function updateAttacksTable(attacks) {
            const tbody = document.getElementById('attacks-table');
            tbody.innerHTML = '';
            
            attacks.forEach(attack => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${attack.timestamp}</td>
                    <td>${attack.ip}</td>
                    <td>${attack.type}</td>
                    <td>${attack.path}</td>
                    <td><span class="status banned">${attack.status}</span></td>
                `;
                tbody.appendChild(row);
            });
        }
        
        // 更新节点状态表格
        function updateNodesTable(nodes) {
            const tbody = document.getElementById('nodes-table');
            tbody.innerHTML = '';
            
            nodes.forEach(node => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${node.hostname}</td>
                    <td><span class="status ${node.status}">${node.status}</span></td>
                    <td>${node.banned_count}</td>
                `;
                tbody.appendChild(row);
            });
        }
        
        // 初始化图表
        async function initChart() {
            try {
                const response = await axios.get('/api/charts/attacks');
                const data = response.data;
                
                const ctx = document.getElementById('attackChart').getContext('2d');
                attackChart = new Chart(ctx, {
                    type: 'line',
                    data: data,
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('初始化图表失败:', error);
            }
        }
        
        // 初始化WebSocket
        function initWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === 'stats_update') {
                    updateStats(data.data);
                } else if (data.type === 'ban' || data.type === 'unban') {
                    loadDashboardData(); // 重新加载数据
                }
            };
            
            ws.onclose = function() {
                console.log('WebSocket连接已关闭，5秒后重连...');
                setTimeout(initWebSocket, 5000);
            };
        }
        
        // 显示封禁模态框
        function showBanModal() {
            document.getElementById('banModal').style.display = 'block';
        }
        
        // 关闭封禁模态框
        function closeBanModal() {
            document.getElementById('banModal').style.display = 'none';
        }
        
        // 封禁IP
        document.getElementById('banForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const ip = document.getElementById('banIp').value;
            const reason = document.getElementById('banReason').value;
            const duration = parseInt(document.getElementById('banDuration').value);
            
            try {
                await axios.post('/api/ban', {
                    ip: ip,
                    reason: reason,
                    duration: duration
                });
                
                alert('IP封禁成功');
                closeBanModal();
                loadDashboardData();
            } catch (error) {
                alert('封禁失败: ' + error.response.data.detail);
            }
        });
        
        // 解封IP
        async function unbanIp(ip) {
            if (confirm(`确定要解封IP ${ip} 吗？`)) {
                try {
                    await axios.post('/api/unban', {
                        ip: ip,
                        reason: '手动解封'
                    });
                    
                    alert('IP解封成功');
                    loadDashboardData();
                } catch (error) {
                    alert('解封失败: ' + error.response.data.detail);
                }
            }
        }
        
        // 点击模态框外部关闭
        window.onclick = function(event) {
            const modal = document.getElementById('banModal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>
        """


def create_app(config: Dict[str, Any]) -> FastAPI:
    """创建Web应用
    
    Args:
        config: 配置字典
    
    Returns:
        FastAPI应用实例
        
    Raises:
        DashboardError: 应用创建失败
    """
    try:
        dashboard = DashboardApp(config)
        return dashboard.app
    except Exception as e:
        logging.error(f"创建Web应用失败: {e}")
        raise DashboardError(f"应用创建失败: {e}") from e


if __name__ == '__main__':
    # 测试运行
    import uvicorn
    import sys
    
    try:
        # 模拟配置
        test_config: Dict[str, Any] = {
            'web': {
                'host': '0.0.0.0',
                'port': 8080,
                'secret_key': 'test-secret-key'
            },
            'central': {
                'api': {
                    'api_key': 'test-api-key'
                }
            }
        }
        
        app = create_app(test_config)
        
        print("🚀 启动Web仪表板...")
        print("📊 访问地址: http://localhost:8080")
        print("🔑 API密钥: test-api-key")
        print("\n按 Ctrl+C 停止服务")
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8080,
            log_level="info"
        )
        
    except KeyboardInterrupt:
        print("\n👋 服务已停止")
        sys.exit(0)
    except Exception as e:
        print(f"❌ 启动失败: {e}")
        sys.exit(1)