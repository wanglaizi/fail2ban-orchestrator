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
import signal
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass

import aiofiles
import aiohttp
import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from utils.logger import setup_logger
from utils.nginx_parser import NginxLogParser
from utils.config import ConfigManager


class LogAgentError(Exception):
    """日志代理异常"""
    pass


class LogParsingError(LogAgentError):
    """日志解析异常"""
    pass


class NetworkError(LogAgentError):
    """网络异常"""
    pass


@dataclass
class AgentStats:
    """代理统计信息"""
    logs_processed: int = 0
    logs_sent: int = 0
    logs_failed: int = 0
    bytes_processed: int = 0
    last_send_time: Optional[datetime] = None
    start_time: datetime = datetime.now()
    errors_count: int = 0


class LogFileHandler(FileSystemEventHandler):
    """日志文件监控处理器"""
    
    def __init__(self, agent: 'LogAgent') -> None:
        self.agent = agent
        super().__init__()
    
    def on_modified(self, event) -> None:
        """文件修改事件处理"""
        try:
            if not event.is_directory and event.src_path == self.agent.log_file_path:
                asyncio.create_task(self.agent.process_new_logs())
        except Exception as e:
            self.agent.logger.error(f"处理文件修改事件失败: {e}")


class LogAgent:
    """日志收集代理"""
    
    def __init__(self, config_path: str = "config/config.yaml") -> None:
        self.config_path = config_path
        self.config_manager = ConfigManager()
        self.config = self._load_config(config_path)
        self.logger = setup_logger("agent", self.config)
        
        # 配置信息
        self.node_id: str = self.config['system']['node_id']
        self.log_file_path: str = self.config['agent']['nginx']['access_log']
        self.central_server: Dict[str, Any] = self.config['agent']['central_server']
        
        # 日志解析器
        self.parser = NginxLogParser(self.config['agent']['nginx']['log_format'])
        
        # 状态管理
        self.last_position: int = 0
        self.log_buffer: List[Dict] = []
        self.running: bool = False
        
        # HTTP会话
        self.session: Optional[aiohttp.ClientSession] = None
        
        # 文件监控
        self.observer = Observer()
        self.file_handler = LogFileHandler(self)
        
        # 统计信息
        self.stats = AgentStats()
        
        # 重试配置
        self.max_retries: int = self.config.get('agent', {}).get('max_retries', 3)
        self.retry_delay: float = self.config.get('agent', {}).get('retry_delay', 5.0)
        
        # 批处理配置
        self.batch_size: int = self.config.get('agent', {}).get('batch_size', 100)
        self.max_buffer_size: int = self.config.get('agent', {}).get('max_buffer_size', 1000)
    
    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            return self.config_manager.load_config(self.config_path)
        except Exception as e:
            raise LogAgentError(f"加载配置文件失败: {e}") from e
    
    async def reload_config(self) -> None:
        """重新加载配置"""
        try:
            old_config = self.config.copy()
            self.config = self._load_config()
            
            # 检查关键配置是否变化
            if old_config.get('agent', {}).get('nginx', {}).get('access_log') != self.config.get('agent', {}).get('nginx', {}).get('access_log'):
                self.logger.warning("日志文件路径已更改，需要重启代理")
            
            self.logger.info("配置已重新加载")
            
        except Exception as e:
            self.logger.error(f"重新加载配置失败: {e}")
            raise LogAgentError(f"重新加载配置失败: {e}") from e
    
    async def init_session(self) -> None:
        """初始化HTTP会话"""
        try:
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=5,
                keepalive_timeout=30,
                enable_cleanup_closed=True
            )
            
            headers = {
                'X-API-Key': self.central_server['api_key'],
                'Content-Type': 'application/json',
                'User-Agent': f'Fail2ban-Agent/{self.node_id}'
            }
            
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self.session = aiohttp.ClientSession(
                connector=connector,
                headers=headers,
                timeout=timeout
            )
            
            self.logger.info("HTTP会话初始化成功")
            
        except Exception as e:
            raise NetworkError(f"初始化HTTP会话失败: {e}") from e
    
    async def load_last_position(self) -> None:
        """加载上次读取位置"""
        position_file = Path(f"/tmp/fail2ban_agent_{self.node_id}.pos")
        try:
            if position_file.exists():
                async with aiofiles.open(position_file, 'r') as f:
                    content = await f.read()
                    self.last_position = int(content.strip())
                    self.logger.info(f"加载上次读取位置: {self.last_position}")
            else:
                self.last_position = 0
                self.logger.info("首次运行，从文件末尾开始读取")
                # 获取文件当前大小作为起始位置
                try:
                    file_path = Path(self.log_file_path)
                    if file_path.exists():
                        self.last_position = file_path.stat().st_size
                except Exception as e:
                    self.logger.warning(f"获取文件大小失败: {e}")
        except (ValueError, OSError) as e:
            self.logger.error(f"加载位置文件失败: {e}")
            self.last_position = 0
        except Exception as e:
            self.logger.error(f"加载位置文件异常: {e}")
            self.last_position = 0
    
    async def save_last_position(self) -> None:
        """保存当前读取位置"""
        position_file = Path(f"/tmp/fail2ban_agent_{self.node_id}.pos")
        try:
            async with aiofiles.open(position_file, 'w') as f:
                await f.write(str(self.last_position))
        except Exception as e:
            self.logger.error(f"保存位置文件失败: {e}")
    
    async def process_new_logs(self) -> None:
        """处理新的日志条目"""
        try:
            file_path = Path(self.log_file_path)
            if not file_path.exists():
                self.logger.warning(f"日志文件不存在: {self.log_file_path}")
                return
            
            current_size = file_path.stat().st_size
            
            # 检查文件是否被轮转
            if current_size < self.last_position:
                self.logger.info("检测到日志文件轮转，重置读取位置")
                self.last_position = 0
            
            # 读取新内容
            if current_size > self.last_position:
                try:
                    async with aiofiles.open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        await f.seek(self.last_position)
                        new_content = await f.read()
                        
                        if new_content:
                            lines = new_content.strip().split('\n')
                            processed_count = 0
                            
                            for line in lines:
                                if line.strip():
                                    try:
                                        parsed_log = self.parser.parse(line)
                                        if parsed_log:
                                            log_entry = {
                                                'timestamp': datetime.now().isoformat(),
                                                'node_id': self.node_id,
                                                'raw_log': line,
                                                'parsed_log': parsed_log
                                            }
                                            
                                            self.log_buffer.append(log_entry)
                                            processed_count += 1
                                            self.stats.logs_processed += 1
                                            self.stats.bytes_processed += len(line.encode('utf-8'))
                                            
                                            # 检查缓冲区大小
                                            if len(self.log_buffer) >= self.max_buffer_size:
                                                self.logger.warning(f"日志缓冲区已满 ({self.max_buffer_size})，强制发送")
                                                await self.send_logs()
                                                
                                    except LogParsingError as e:
                                        self.logger.warning(f"解析日志行失败: {e}, 行内容: {line[:100]}...")
                                        self.stats.errors_count += 1
                                    except Exception as e:
                                        self.logger.error(f"处理日志行异常: {e}, 行内容: {line[:100]}...")
                                        self.stats.errors_count += 1
                            
                            # 更新位置
                            self.last_position = current_size
                            
                            # 保存位置
                            await self.save_last_position()
                            
                            if processed_count > 0:
                                self.logger.debug(f"处理了 {processed_count} 行新日志，缓冲区大小: {len(self.log_buffer)}")
                            
                            # 如果缓冲区达到批量大小，发送日志
                            batch_size = self.config['agent']['sender']['batch_size']
                            if len(self.log_buffer) >= batch_size:
                                await self.send_logs()
                                
                except UnicodeDecodeError as e:
                    self.logger.error(f"日志文件编码错误: {e}")
                    self.stats.errors_count += 1
                except OSError as e:
                    self.logger.error(f"读取日志文件失败: {e}")
                    self.stats.errors_count += 1
        
        except Exception as e:
            self.logger.error(f"处理新日志失败: {e}")
            self.stats.errors_count += 1
            raise LogAgentError(f"处理新日志失败: {e}") from e
    
    async def send_logs(self) -> None:
        """发送日志到中央服务器"""
        if not self.log_buffer:
            return
        
        # 分批发送
        batch_size = min(self.batch_size, len(self.log_buffer))
        logs_to_send = self.log_buffer[:batch_size]
        
        payload = {
            'node_id': self.node_id,
            'logs': logs_to_send,
            'timestamp': datetime.now().isoformat(),
            'batch_size': len(logs_to_send)
        }
        
        url = f"http://{self.central_server['host']}:{self.central_server['port']}/api/logs/submit"
        
        # 重试机制
        for attempt in range(self.max_retries):
            try:
                if not self.session:
                    await self.init_session()
                
                async with self.session.post(url, json=payload) as response:
                    if response.status == 200:
                        # 发送成功
                        self.log_buffer = self.log_buffer[batch_size:]
                        self.stats.logs_sent += len(logs_to_send)
                        self.stats.last_send_time = datetime.now()
                        
                        self.logger.info(f"成功发送 {len(logs_to_send)} 条日志 (剩余: {len(self.log_buffer)})")
                        return
                    
                    elif response.status == 429:  # 限流
                        self.logger.warning(f"服务器限流，等待 {self.retry_delay} 秒后重试")
                        await asyncio.sleep(self.retry_delay)
                        continue
                    
                    else:
                        error_text = await response.text()
                        self.logger.error(f"发送日志失败，状态码: {response.status}, 响应: {error_text}")
                        
                        if attempt == self.max_retries - 1:
                            await self._save_failed_logs(payload)
                            self.stats.logs_failed += len(logs_to_send)
                        else:
                            await asyncio.sleep(self.retry_delay * (attempt + 1))
            
            except aiohttp.ClientError as e:
                self.logger.error(f"网络错误 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                if attempt == self.max_retries - 1:
                    await self._save_failed_logs(payload)
                    self.stats.logs_failed += len(logs_to_send)
                    raise NetworkError(f"发送日志网络错误: {e}") from e
                else:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
            
            except Exception as e:
                self.logger.error(f"发送日志异常 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                if attempt == self.max_retries - 1:
                    await self._save_failed_logs(payload)
                    self.stats.logs_failed += len(logs_to_send)
                    self.stats.errors_count += 1
                    raise LogAgentError(f"发送日志失败: {e}") from e
                else:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
    
    async def _save_failed_logs(self, payload: Dict[str, Any]) -> None:
        """保存发送失败的日志"""
        try:
            failed_log_file = Path(f"/tmp/fail2ban_failed_logs_{self.node_id}.json")
            
            # 添加失败信息
            failed_payload = payload.copy()
            failed_payload.update({
                'failed_at': datetime.now().isoformat(),
                'retry_count': 0,
                'node_id': self.node_id
            })
            
            # 确保目录存在
            failed_log_file.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiofiles.open(failed_log_file, 'a', encoding='utf-8') as f:
                await f.write(json.dumps(failed_payload, ensure_ascii=False) + '\n')
            
            self.logger.info(f"失败日志已保存到: {failed_log_file} ({len(payload.get('logs', []))} 条)")
            
        except Exception as e:
            self.logger.error(f"保存失败日志异常: {e}")
    
    async def retry_failed_logs(self) -> None:
        """重试发送失败的日志"""
        failed_log_file = Path(f"/tmp/fail2ban_failed_logs_{self.node_id}.json")
        
        try:
            if not failed_log_file.exists():
                return
            
            async with aiofiles.open(failed_log_file, 'r', encoding='utf-8') as f:
                lines = await f.readlines()
            
            if not lines:
                return
            
            self.logger.info(f"尝试重新发送 {len(lines)} 批失败日志")
            
            successful_lines = []
            url = f"http://{self.central_server['host']}:{self.central_server['port']}/api/logs/submit"
            
            for line in lines:
                try:
                    payload = json.loads(line.strip())
                    
                    # 检查重试次数
                    retry_count = payload.get('retry_count', 0)
                    if retry_count >= self.max_retries:
                        self.logger.warning(f"跳过已达最大重试次数的日志批次")
                        continue
                    
                    # 移除失败相关字段
                    clean_payload = {
                        'node_id': payload['node_id'],
                        'logs': payload['logs'],
                        'timestamp': payload['timestamp'],
                        'batch_size': payload.get('batch_size', len(payload['logs']))
                    }
                    
                    if not self.session:
                        await self.init_session()
                    
                    async with self.session.post(url, json=clean_payload) as response:
                        if response.status == 200:
                            successful_lines.append(line)
                            self.stats.logs_sent += len(clean_payload['logs'])
                            self.logger.info(f"成功重发 {len(clean_payload['logs'])} 条日志")
                        else:
                            # 更新重试次数
                            payload['retry_count'] = retry_count + 1
                            payload['last_retry_at'] = datetime.now().isoformat()
                            self.logger.warning(f"重发失败，状态码: {response.status}")
                
                except json.JSONDecodeError as e:
                    self.logger.error(f"解析失败日志JSON异常: {e}")
                    successful_lines.append(line)  # 移除损坏的行
                except Exception as e:
                    self.logger.error(f"重发日志异常: {e}")
            
            # 更新失败日志文件
            if successful_lines:
                remaining_lines = [line for line in lines if line not in successful_lines]
                
                if remaining_lines:
                    async with aiofiles.open(failed_log_file, 'w', encoding='utf-8') as f:
                        await f.writelines(remaining_lines)
                    self.logger.info(f"成功重发 {len(successful_lines)} 批日志，剩余 {len(remaining_lines)} 批")
                else:
                    # 删除文件
                    failed_log_file.unlink()
                    self.logger.info("所有失败日志已成功重发")
        
        except Exception as e:
            self.logger.error(f"重试失败日志异常: {e}")
            self.stats.errors_count += 1
    
    def start_file_monitoring(self) -> None:
        """启动文件监控"""
        try:
            log_dir = Path(self.log_file_path).parent
            if not log_dir.exists():
                self.logger.warning(f"日志目录不存在: {log_dir}")
                return
            
            self.observer.schedule(self.file_handler, str(log_dir), recursive=False)
            self.observer.start()
            self.logger.info(f"开始监控日志文件: {self.log_file_path}")
        except Exception as e:
            self.logger.error(f"启动文件监控失败: {e}")
            raise LogAgentError(f"启动文件监控失败: {e}") from e
    
    def stop_file_monitoring(self) -> None:
        """停止文件监控"""
        try:
            if self.observer.is_alive():
                self.observer.stop()
                self.observer.join(timeout=5)
                self.logger.info("文件监控已停止")
        except Exception as e:
            self.logger.error(f"停止文件监控失败: {e}")
    
    async def periodic_send(self) -> None:
        """定期发送日志"""
        interval = self.config.get('agent', {}).get('sender', {}).get('interval', 30)
        
        while self.running:
            try:
                await asyncio.sleep(interval)
                
                if self.log_buffer:
                    await self.send_logs()
                
                # 定期重试失败的日志
                await self.retry_failed_logs()
                
            except asyncio.CancelledError:
                self.logger.info("定期发送任务被取消")
                break
            except Exception as e:
                self.logger.error(f"定期发送任务异常: {e}")
                self.stats.errors_count += 1
                await asyncio.sleep(5)  # 错误后短暂等待
    
    async def health_check(self) -> None:
        """健康检查"""
        check_interval = 60  # 每分钟检查一次
        
        while self.running:
            try:
                await asyncio.sleep(check_interval)
                
                # 检查中央服务器连接
                try:
                    if not self.session:
                        await self.init_session()
                    
                    url = f"http://{self.central_server['host']}:{self.central_server['port']}/api/status"
                    
                    async with self.session.get(url) as response:
                        if response.status == 200:
                            self.logger.debug("中央服务器连接正常")
                        else:
                            self.logger.warning(f"中央服务器响应异常: {response.status}")
                            
                except aiohttp.ClientError as e:
                    self.logger.warning(f"中央服务器连接失败: {e}")
                except Exception as e:
                    self.logger.error(f"检查中央服务器连接异常: {e}")
                
                # 检查日志文件状态
                log_file = Path(self.log_file_path)
                if not log_file.exists():
                    self.logger.warning(f"日志文件不存在: {self.log_file_path}")
                elif not log_file.is_file():
                    self.logger.warning(f"日志路径不是文件: {self.log_file_path}")
                
                # 检查缓冲区状态
                if len(self.log_buffer) > self.max_buffer_size * 0.8:
                    self.logger.warning(f"日志缓冲区接近满载: {len(self.log_buffer)}/{self.max_buffer_size}")
                
                # 记录统计信息
                uptime = datetime.now() - self.stats.start_time
                self.logger.debug(
                    f"代理运行状态 - 运行时间: {uptime}, "
                    f"已处理: {self.stats.logs_processed}, "
                    f"已发送: {self.stats.logs_sent}, "
                    f"失败: {self.stats.logs_failed}, "
                    f"错误: {self.stats.errors_count}"
                )
                
            except asyncio.CancelledError:
                self.logger.info("健康检查任务被取消")
                break
            except Exception as e:
                self.logger.error(f"健康检查失败: {e}")
                self.stats.errors_count += 1
    
    async def get_stats(self) -> Dict[str, Any]:
        """获取代理统计信息"""
        uptime = datetime.now() - self.stats.start_time
        return {
            'node_id': self.node_id,
            'uptime_seconds': uptime.total_seconds(),
            'logs_processed': self.stats.logs_processed,
            'logs_sent': self.stats.logs_sent,
            'logs_failed': self.stats.logs_failed,
            'bytes_processed': self.stats.bytes_processed,
            'errors_count': self.stats.errors_count,
            'buffer_size': len(self.log_buffer),
            'last_send_time': self.stats.last_send_time.isoformat() if self.stats.last_send_time else None,
            'running': self.running,
            'log_file_path': self.log_file_path,
            'last_position': self.last_position
        }
    
    async def start(self) -> None:
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
            self.background_tasks = [
                asyncio.create_task(self.periodic_send(), name="periodic_send"),
                asyncio.create_task(self.health_check(), name="health_check")
            ]
            
            self.logger.info("日志收集代理启动成功")
            
            # 等待任务完成或被取消
            try:
                await asyncio.gather(*self.background_tasks, return_exceptions=True)
            except Exception as e:
                self.logger.error(f"后台任务异常: {e}")
                raise
            
        except Exception as e:
            self.logger.error(f"代理启动失败: {e}")
            await self.stop()  # 清理资源
            raise LogAgentError(f"代理启动失败: {e}") from e
    
    async def stop(self) -> None:
        """停止代理"""
        self.logger.info("正在停止日志收集代理...")
        
        # 设置停止标志
        self.running = False
        
        # 取消后台任务
        if hasattr(self, 'background_tasks'):
            for task in self.background_tasks:
                if not task.done():
                    task.cancel()
            
            # 等待任务完成
            try:
                await asyncio.gather(*self.background_tasks, return_exceptions=True)
            except Exception as e:
                self.logger.warning(f"停止后台任务时出现异常: {e}")
        
        # 发送剩余日志
        try:
            if self.log_buffer:
                self.logger.info(f"发送剩余的 {len(self.log_buffer)} 条日志")
                await self.send_logs()
        except Exception as e:
            self.logger.error(f"发送剩余日志失败: {e}")
        
        # 保存位置
        try:
            await self.save_last_position()
        except Exception as e:
            self.logger.error(f"保存位置失败: {e}")
        
        # 停止文件监控
        try:
            self.stop_file_monitoring()
        except Exception as e:
            self.logger.error(f"停止文件监控失败: {e}")
        
        # 关闭HTTP会话
        try:
            if self.session and not self.session.closed:
                await self.session.close()
        except Exception as e:
            self.logger.error(f"关闭HTTP会话失败: {e}")
        
        # 输出最终统计信息
        final_stats = await self.get_stats()
        self.logger.info(f"代理已停止 - 最终统计: {final_stats}")
        
        self.logger.info("日志收集代理已完全停止")


async def main() -> None:
    """主函数"""
    import sys
    import argparse
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='Fail2ban日志收集代理')
    parser.add_argument('--config', '-c', default='config/config.yaml', help='配置文件路径')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    parser.add_argument('--stats-interval', type=int, default=300, help='统计信息输出间隔(秒)')
    
    args = parser.parse_args()
    
    agent = None
    
    try:
        # 创建代理实例
        agent = LogAgent(args.config)
        
        if args.verbose:
            agent.logger.setLevel('DEBUG')
        
        # 设置信号处理
        def signal_handler(signum, frame):
            print(f"\n收到信号 {signum}，正在关闭代理...")
            if agent:
                asyncio.create_task(agent.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # 启动代理
        await agent.start()
        
    except KeyboardInterrupt:
        print("\n收到键盘中断信号")
    except LogAgentError as e:
        print(f"代理错误: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"未知错误: {e}")
        sys.exit(1)
    finally:
        if agent:
            try:
                await agent.stop()
            except Exception as e:
                print(f"停止代理时出错: {e}")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"程序异常退出: {e}")
        import sys
        sys.exit(1)