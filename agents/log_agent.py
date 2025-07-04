#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 日志收集代理
负责监控nginx日志文件，解析日志并发送到中央控制节点
"""

import asyncio
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import aiofiles
import aiohttp
import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from utils.logger import setup_logger
from utils.nginx_parser import NginxLogParser


class LogFileHandler(FileSystemEventHandler):
    """日志文件监控处理器"""
    
    def __init__(self, agent):
        self.agent = agent
        super().__init__()
    
    def on_modified(self, event):
        """文件修改事件处理"""
        if not event.is_directory and event.src_path == self.agent.log_file_path:
            asyncio.create_task(self.agent.process_new_logs())


class LogAgent:
    """日志收集代理"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self._load_config(config_path)
        self.logger = setup_logger("agent", self.config)
        
        # 配置信息
        self.node_id = self.config['system']['node_id']
        self.log_file_path = self.config['agent']['nginx']['access_log']
        self.central_server = self.config['agent']['central_server']
        
        # 日志解析器
        self.parser = NginxLogParser(self.config['agent']['nginx']['log_format'])
        
        # 状态管理
        self.last_position = 0
        self.log_buffer: List[Dict] = []
        self.running = False
        
        # HTTP会话
        self.session: Optional[aiohttp.ClientSession] = None
        
        # 文件监控
        self.observer = Observer()
        self.file_handler = LogFileHandler(self)
    
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
    
    async def load_last_position(self):
        """加载上次读取位置"""
        position_file = f"/tmp/fail2ban_agent_{self.node_id}.pos"
        try:
            async with aiofiles.open(position_file, 'r') as f:
                content = await f.read()
                self.last_position = int(content.strip())
                self.logger.info(f"加载上次读取位置: {self.last_position}")
        except FileNotFoundError:
            self.last_position = 0
            self.logger.info("首次运行，从文件末尾开始读取")
            # 获取文件当前大小作为起始位置
            try:
                file_path = Path(self.log_file_path)
                if file_path.exists():
                    self.last_position = file_path.stat().st_size
            except Exception as e:
                self.logger.warning(f"获取文件大小失败: {e}")
        except Exception as e:
            self.logger.error(f"加载位置文件失败: {e}")
            self.last_position = 0
    
    async def save_last_position(self):
        """保存当前读取位置"""
        position_file = f"/tmp/fail2ban_agent_{self.node_id}.pos"
        try:
            async with aiofiles.open(position_file, 'w') as f:
                await f.write(str(self.last_position))
        except Exception as e:
            self.logger.error(f"保存位置文件失败: {e}")
    
    async def process_new_logs(self):
        """处理新的日志条目"""
        try:
            async with aiofiles.open(self.log_file_path, 'r') as f:
                # 移动到上次读取位置
                await f.seek(self.last_position)
                
                # 读取新内容
                new_content = await f.read()
                
                if not new_content:
                    return
                
                # 更新位置
                self.last_position = await f.tell()
                
                # 按行分割
                lines = new_content.strip().split('\n')
                
                # 解析每一行
                for line in lines:
                    if line.strip():
                        parsed_log = self.parser.parse(line)
                        if parsed_log:
                            self.log_buffer.append(parsed_log)
                
                self.logger.debug(f"处理了 {len(lines)} 行新日志")
                
                # 如果缓冲区达到批量大小，发送日志
                batch_size = self.config['agent']['sender']['batch_size']
                if len(self.log_buffer) >= batch_size:
                    await self.send_logs()
                
                # 保存位置
                await self.save_last_position()
                
        except Exception as e:
            self.logger.error(f"处理日志失败: {e}")
    
    async def send_logs(self):
        """发送日志到中央服务器"""
        if not self.log_buffer:
            return
        
        try:
            url = f"http://{self.central_server['host']}:{self.central_server['port']}/api/logs/submit"
            
            payload = {
                'node_id': self.node_id,
                'logs': self.log_buffer.copy(),
                'timestamp': datetime.now().isoformat()
            }
            
            retry_count = self.config['agent']['sender']['retry_count']
            
            for attempt in range(retry_count + 1):
                try:
                    async with self.session.post(url, json=payload) as response:
                        if response.status == 200:
                            result = await response.json()
                            self.logger.info(
                                f"成功发送 {len(self.log_buffer)} 条日志到中央服务器"
                            )
                            self.log_buffer.clear()
                            return
                        else:
                            error_text = await response.text()
                            self.logger.error(
                                f"发送日志失败，状态码: {response.status}, "
                                f"响应: {error_text}"
                            )
                
                except aiohttp.ClientError as e:
                    self.logger.error(f"网络请求失败 (尝试 {attempt + 1}/{retry_count + 1}): {e}")
                    
                    if attempt < retry_count:
                        await asyncio.sleep(2 ** attempt)  # 指数退避
                    else:
                        self.logger.error("达到最大重试次数，日志发送失败")
                        # 可以选择将失败的日志保存到本地文件
                        await self._save_failed_logs(payload)
        
        except Exception as e:
            self.logger.error(f"发送日志异常: {e}")
            await self._save_failed_logs({'logs': self.log_buffer.copy()})
    
    async def _save_failed_logs(self, payload: dict):
        """保存发送失败的日志"""
        try:
            failed_log_file = f"/tmp/fail2ban_failed_logs_{self.node_id}.json"
            
            # 添加时间戳
            payload['failed_at'] = datetime.now().isoformat()
            
            async with aiofiles.open(failed_log_file, 'a') as f:
                await f.write(json.dumps(payload) + '\n')
            
            self.logger.info(f"失败日志已保存到: {failed_log_file}")
            
        except Exception as e:
            self.logger.error(f"保存失败日志异常: {e}")
    
    async def retry_failed_logs(self):
        """重试发送失败的日志"""
        failed_log_file = f"/tmp/fail2ban_failed_logs_{self.node_id}.json"
        
        try:
            if not Path(failed_log_file).exists():
                return
            
            async with aiofiles.open(failed_log_file, 'r') as f:
                lines = await f.readlines()
            
            if not lines:
                return
            
            self.logger.info(f"尝试重新发送 {len(lines)} 批失败日志")
            
            successful_lines = []
            
            for line in lines:
                try:
                    payload = json.loads(line.strip())
                    
                    # 移除失败时间戳
                    payload.pop('failed_at', None)
                    
                    url = f"http://{self.central_server['host']}:{self.central_server['port']}/api/logs/submit"
                    
                    async with self.session.post(url, json=payload) as response:
                        if response.status == 200:
                            successful_lines.append(line)
                            self.logger.info(f"成功重发 {len(payload.get('logs', []))} 条日志")
                        else:
                            self.logger.warning(f"重发失败，状态码: {response.status}")
                
                except Exception as e:
                    self.logger.error(f"重发日志异常: {e}")
            
            # 移除成功发送的日志
            if successful_lines:
                remaining_lines = [line for line in lines if line not in successful_lines]
                
                if remaining_lines:
                    async with aiofiles.open(failed_log_file, 'w') as f:
                        await f.writelines(remaining_lines)
                else:
                    # 删除文件
                    Path(failed_log_file).unlink()
                    self.logger.info("所有失败日志已成功重发")
        
        except Exception as e:
            self.logger.error(f"重试失败日志异常: {e}")
    
    def start_file_monitoring(self):
        """启动文件监控"""
        try:
            log_dir = Path(self.log_file_path).parent
            self.observer.schedule(self.file_handler, str(log_dir), recursive=False)
            self.observer.start()
            self.logger.info(f"开始监控日志文件: {self.log_file_path}")
        except Exception as e:
            self.logger.error(f"启动文件监控失败: {e}")
    
    def stop_file_monitoring(self):
        """停止文件监控"""
        try:
            self.observer.stop()
            self.observer.join()
            self.logger.info("文件监控已停止")
        except Exception as e:
            self.logger.error(f"停止文件监控失败: {e}")
    
    async def periodic_send(self):
        """定期发送日志"""
        interval = self.config['agent']['sender']['interval']
        
        while self.running:
            try:
                await asyncio.sleep(interval)
                
                if self.log_buffer:
                    await self.send_logs()
                
                # 定期重试失败的日志
                await self.retry_failed_logs()
                
            except Exception as e:
                self.logger.error(f"定期发送任务异常: {e}")
    
    async def health_check(self):
        """健康检查"""
        while self.running:
            try:
                await asyncio.sleep(60)  # 每分钟检查一次
                
                # 检查中央服务器连接
                url = f"http://{self.central_server['host']}:{self.central_server['port']}/api/status"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        self.logger.debug("中央服务器连接正常")
                    else:
                        self.logger.warning(f"中央服务器响应异常: {response.status}")
                
                # 检查日志文件是否存在
                if not Path(self.log_file_path).exists():
                    self.logger.warning(f"日志文件不存在: {self.log_file_path}")
                
            except Exception as e:
                self.logger.error(f"健康检查失败: {e}")
    
    async def start(self):
        """启动代理"""
        try:
            self.logger.info(f"启动日志收集代理，节点ID: {self.node_id}")
            
            # 初始化HTTP会话
            await self.init_session()
            
            # 加载上次读取位置
            await self.load_last_position()
            
            # 启动文件监控
            self.start_file_monitoring()
            
            # 设置运行状态
            self.running = True
            
            # 启动后台任务
            tasks = [
                asyncio.create_task(self.periodic_send()),
                asyncio.create_task(self.health_check())
            ]
            
            self.logger.info("日志收集代理启动成功")
            
            # 等待任务完成
            await asyncio.gather(*tasks)
            
        except Exception as e:
            self.logger.error(f"代理启动失败: {e}")
            raise
    
    async def stop(self):
        """停止代理"""
        self.logger.info("正在停止日志收集代理...")
        
        self.running = False
        
        # 发送剩余日志
        if self.log_buffer:
            await self.send_logs()
        
        # 保存位置
        await self.save_last_position()
        
        # 停止文件监控
        self.stop_file_monitoring()
        
        # 关闭HTTP会话
        if self.session:
            await self.session.close()
        
        self.logger.info("日志收集代理已停止")


if __name__ == '__main__':
    import sys
    import signal
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"
    
    agent = LogAgent(config_path)
    
    # 信号处理
    def signal_handler(signum, frame):
        print("\n收到停止信号，正在关闭代理...")
        asyncio.create_task(agent.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        print("\n代理已停止")
    except Exception as e:
        print(f"代理运行错误: {e}")
        sys.exit(1)