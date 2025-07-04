#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - Fail2ban管理器
"""

import asyncio
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional


class Fail2banManager:
    """Fail2ban管理器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.jail_name = "distributed-ban"
        self.fail2ban_config = config.get('executor', {}).get('fail2ban', {})
        
        # 配置路径
        self.config_path = self.fail2ban_config.get('config_path', '/etc/fail2ban')
        self.jail_config_file = self.fail2ban_config.get('jail_config', '/etc/fail2ban/jail.d/distributed.conf')
        self.action_config_file = self.fail2ban_config.get('action_config', '/etc/fail2ban/action.d/distributed.conf')
        
        # 状态跟踪
        self.banned_ips: Dict[str, Dict] = {}
    
    async def initialize(self):
        """初始化Fail2ban配置"""
        try:
            # 创建配置目录
            await self._ensure_config_directories()
            
            # 生成配置文件
            await self._generate_jail_config()
            await self._generate_action_config()
            
            # 重载Fail2ban配置
            await self._reload_fail2ban()
            
            print("Fail2ban管理器初始化成功")
            
        except Exception as e:
            print(f"Fail2ban管理器初始化失败: {e}")
            raise
    
    async def _ensure_config_directories(self):
        """确保配置目录存在"""
        directories = [
            Path(self.config_path),
            Path(self.config_path) / 'jail.d',
            Path(self.config_path) / 'action.d',
            Path(self.config_path) / 'filter.d'
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    async def _generate_jail_config(self):
        """生成jail配置文件"""
        jail_config = f"""
# 分布式Fail2ban Jail配置
# 由分布式Fail2ban系统自动生成

[{self.jail_name}]
enabled = true
filter = distributed-filter
action = distributed-action
logpath = /dev/null
maxretry = 1
findtime = 86400
bantime = 3600
"""
        
        try:
            with open(self.jail_config_file, 'w', encoding='utf-8') as f:
                f.write(jail_config)
            
            print(f"Jail配置文件已生成: {self.jail_config_file}")
            
        except Exception as e:
            print(f"生成jail配置文件失败: {e}")
            raise
    
    async def _generate_action_config(self):
        """生成action配置文件"""
        action_config = """
# 分布式Fail2ban Action配置
# 由分布式Fail2ban系统自动生成

[Definition]

# 封禁动作
actionstart = 
actionstop = 
actioncheck = 
actionban = iptables -I INPUT -s <ip> -j DROP
actionunban = iptables -D INPUT -s <ip> -j DROP

[Init]
# 初始化参数
name = distributed-action
"""
        
        try:
            with open(self.action_config_file, 'w', encoding='utf-8') as f:
                f.write(action_config)
            
            print(f"Action配置文件已生成: {self.action_config_file}")
            
        except Exception as e:
            print(f"生成action配置文件失败: {e}")
            raise
    
    async def _generate_filter_config(self):
        """生成filter配置文件"""
        filter_config_file = Path(self.config_path) / 'filter.d' / 'distributed-filter.conf'
        
        filter_config = """
# 分布式Fail2ban Filter配置
# 由分布式Fail2ban系统自动生成

[Definition]
# 这是一个虚拟过滤器，实际的检测由分布式系统完成
failregex = ^.*$
ignoreregex = 
"""
        
        try:
            with open(filter_config_file, 'w', encoding='utf-8') as f:
                f.write(filter_config)
            
            print(f"Filter配置文件已生成: {filter_config_file}")
            
        except Exception as e:
            print(f"生成filter配置文件失败: {e}")
            raise
    
    async def _reload_fail2ban(self):
        """重载Fail2ban配置"""
        try:
            # 重载配置
            result = await self._run_command(['fail2ban-client', 'reload'])
            
            if result.returncode == 0:
                print("Fail2ban配置重载成功")
            else:
                print(f"Fail2ban配置重载失败: {result.stderr}")
            
            # 启动jail
            await asyncio.sleep(2)  # 等待重载完成
            await self._start_jail()
            
        except Exception as e:
            print(f"重载Fail2ban配置异常: {e}")
    
    async def _start_jail(self):
        """启动jail"""
        try:
            result = await self._run_command(['fail2ban-client', 'start', self.jail_name])
            
            if result.returncode == 0:
                print(f"Jail {self.jail_name} 启动成功")
            else:
                # 如果已经启动，忽略错误
                if 'already exists' not in result.stderr:
                    print(f"启动jail失败: {result.stderr}")
        
        except Exception as e:
            print(f"启动jail异常: {e}")
    
    async def ban_ip(self, ip: str, duration: int = 60, reason: str = "Distributed ban") -> bool:
        """封禁IP地址
        
        Args:
            ip: 要封禁的IP地址
            duration: 封禁时长（分钟）
            reason: 封禁原因
        
        Returns:
            是否成功
        """
        try:
            # 检查IP是否已经被封禁
            if await self._is_ip_banned(ip):
                print(f"IP {ip} 已经被封禁")
                return True
            
            # 使用fail2ban-client封禁IP
            result = await self._run_command([
                'fail2ban-client', 'set', self.jail_name, 'banip', ip
            ])
            
            if result.returncode == 0:
                # 记录封禁信息
                self.banned_ips[ip] = {
                    'banned_at': datetime.now(),
                    'duration': duration,
                    'reason': reason,
                    'expires_at': datetime.now() + timedelta(minutes=duration)
                }
                
                print(f"IP {ip} 封禁成功，时长: {duration}分钟，原因: {reason}")
                
                # 设置自动解封
                if duration > 0:
                    asyncio.create_task(self._schedule_unban(ip, duration * 60))
                
                return True
            else:
                print(f"封禁IP {ip} 失败: {result.stderr}")
                return False
        
        except Exception as e:
            print(f"封禁IP {ip} 异常: {e}")
            return False
    
    async def unban_ip(self, ip: str) -> bool:
        """解封IP地址
        
        Args:
            ip: 要解封的IP地址
        
        Returns:
            是否成功
        """
        try:
            # 使用fail2ban-client解封IP
            result = await self._run_command([
                'fail2ban-client', 'set', self.jail_name, 'unbanip', ip
            ])
            
            if result.returncode == 0:
                # 移除封禁记录
                self.banned_ips.pop(ip, None)
                print(f"IP {ip} 解封成功")
                return True
            else:
                print(f"解封IP {ip} 失败: {result.stderr}")
                return False
        
        except Exception as e:
            print(f"解封IP {ip} 异常: {e}")
            return False
    
    async def _schedule_unban(self, ip: str, delay_seconds: int):
        """计划自动解封
        
        Args:
            ip: IP地址
            delay_seconds: 延迟秒数
        """
        try:
            await asyncio.sleep(delay_seconds)
            
            # 检查IP是否仍在封禁列表中
            if ip in self.banned_ips:
                await self.unban_ip(ip)
        
        except Exception as e:
            print(f"自动解封IP {ip} 异常: {e}")
    
    async def _is_ip_banned(self, ip: str) -> bool:
        """检查IP是否已被封禁
        
        Args:
            ip: IP地址
        
        Returns:
            是否已被封禁
        """
        try:
            result = await self._run_command([
                'fail2ban-client', 'get', self.jail_name, 'banip', '--with-time'
            ])
            
            if result.returncode == 0:
                banned_list = result.stdout.strip()
                return ip in banned_list
            
            return False
        
        except Exception:
            return False
    
    async def get_banned_ips(self) -> List[str]:
        """获取当前封禁的IP列表
        
        Returns:
            封禁的IP列表
        """
        try:
            result = await self._run_command([
                'fail2ban-client', 'get', self.jail_name, 'banip'
            ])
            
            if result.returncode == 0:
                banned_list = result.stdout.strip()
                if banned_list:
                    return banned_list.split('\n')
            
            return []
        
        except Exception as e:
            print(f"获取封禁IP列表异常: {e}")
            return []
    
    async def get_jail_status(self) -> Dict:
        """获取jail状态
        
        Returns:
            jail状态信息
        """
        try:
            result = await self._run_command([
                'fail2ban-client', 'status', self.jail_name
            ])
            
            if result.returncode == 0:
                status_text = result.stdout
                
                # 解析状态信息
                status = {'raw': status_text}
                
                for line in status_text.split('\n'):
                    if 'Currently failed:' in line:
                        status['currently_failed'] = int(line.split(':')[1].strip())
                    elif 'Total failed:' in line:
                        status['total_failed'] = int(line.split(':')[1].strip())
                    elif 'Currently banned:' in line:
                        status['currently_banned'] = int(line.split(':')[1].strip())
                    elif 'Total banned:' in line:
                        status['total_banned'] = int(line.split(':')[1].strip())
                
                return status
            
            return {'error': result.stderr}
        
        except Exception as e:
            return {'error': str(e)}
    
    async def is_service_running(self) -> bool:
        """检查Fail2ban服务是否运行
        
        Returns:
            服务是否运行
        """
        try:
            result = await self._run_command(['fail2ban-client', 'ping'])
            return result.returncode == 0 and 'pong' in result.stdout.lower()
        
        except Exception:
            return False
    
    async def restart_service(self) -> bool:
        """重启Fail2ban服务
        
        Returns:
            是否成功
        """
        try:
            # 停止服务
            await self._run_command(['systemctl', 'stop', 'fail2ban'])
            await asyncio.sleep(2)
            
            # 启动服务
            result = await self._run_command(['systemctl', 'start', 'fail2ban'])
            
            if result.returncode == 0:
                # 等待服务启动
                await asyncio.sleep(5)
                
                # 重新初始化配置
                await self.initialize()
                
                return True
            
            return False
        
        except Exception as e:
            print(f"重启Fail2ban服务异常: {e}")
            return False
    
    async def _run_command(self, command: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """运行系统命令
        
        Args:
            command: 命令列表
            timeout: 超时时间
        
        Returns:
            命令执行结果
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return subprocess.CompletedProcess(
                command,
                process.returncode,
                stdout.decode('utf-8'),
                stderr.decode('utf-8')
            )
        
        except asyncio.TimeoutError:
            print(f"命令执行超时: {' '.join(command)}")
            raise
        except Exception as e:
            print(f"命令执行异常: {e}")
            raise
    
    async def cleanup(self):
        """清理资源"""
        try:
            # 解封所有IP
            for ip in list(self.banned_ips.keys()):
                await self.unban_ip(ip)
            
            print("Fail2ban管理器清理完成")
        
        except Exception as e:
            print(f"Fail2ban管理器清理异常: {e}")
    
    def get_statistics(self) -> Dict:
        """获取统计信息
        
        Returns:
            统计信息
        """
        now = datetime.now()
        active_bans = 0
        expired_bans = 0
        
        for ban_info in self.banned_ips.values():
            if now < ban_info['expires_at']:
                active_bans += 1
            else:
                expired_bans += 1
        
        return {
            'total_bans': len(self.banned_ips),
            'active_bans': active_bans,
            'expired_bans': expired_bans,
            'jail_name': self.jail_name
        }


class IPTablesManager:
    """iptables直接管理器（备用方案）"""
    
    def __init__(self):
        self.chain_name = "FAIL2BAN_DISTRIBUTED"
        self.banned_ips: set = set()
    
    async def initialize(self):
        """初始化iptables链"""
        try:
            # 创建自定义链
            await self._run_command([
                'iptables', '-N', self.chain_name
            ])
            
            # 将自定义链插入到INPUT链
            await self._run_command([
                'iptables', '-I', 'INPUT', '-j', self.chain_name
            ])
            
            print(f"iptables链 {self.chain_name} 初始化成功")
        
        except Exception as e:
            print(f"iptables链初始化失败: {e}")
    
    async def ban_ip(self, ip: str) -> bool:
        """封禁IP
        
        Args:
            ip: IP地址
        
        Returns:
            是否成功
        """
        try:
            if ip in self.banned_ips:
                return True
            
            result = await self._run_command([
                'iptables', '-I', self.chain_name, '-s', ip, '-j', 'DROP'
            ])
            
            if result.returncode == 0:
                self.banned_ips.add(ip)
                print(f"iptables封禁IP {ip} 成功")
                return True
            
            return False
        
        except Exception as e:
            print(f"iptables封禁IP {ip} 异常: {e}")
            return False
    
    async def unban_ip(self, ip: str) -> bool:
        """解封IP
        
        Args:
            ip: IP地址
        
        Returns:
            是否成功
        """
        try:
            result = await self._run_command([
                'iptables', '-D', self.chain_name, '-s', ip, '-j', 'DROP'
            ])
            
            if result.returncode == 0:
                self.banned_ips.discard(ip)
                print(f"iptables解封IP {ip} 成功")
                return True
            
            return False
        
        except Exception as e:
            print(f"iptables解封IP {ip} 异常: {e}")
            return False
    
    async def _run_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """运行命令"""
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout.decode('utf-8'),
            stderr.decode('utf-8')
        )


if __name__ == '__main__':
    # 测试Fail2ban管理器
    import yaml
    
    config = {
        'executor': {
            'fail2ban': {
                'config_path': '/tmp/fail2ban_test',
                'jail_config': '/tmp/fail2ban_test/jail.d/distributed.conf',
                'action_config': '/tmp/fail2ban_test/action.d/distributed.conf'
            }
        }
    }
    
    async def test_manager():
        manager = Fail2banManager(config)
        
        try:
            await manager.initialize()
            print("初始化完成")
            
            # 测试封禁
            await manager.ban_ip('192.168.1.100', 5, 'Test ban')
            
            # 获取状态
            stats = manager.get_statistics()
            print(f"统计信息: {stats}")
            
            # 等待一段时间
            await asyncio.sleep(2)
            
            # 测试解封
            await manager.unban_ip('192.168.1.100')
            
        except Exception as e:
            print(f"测试异常: {e}")
    
    # 运行测试
    asyncio.run(test_manager())
    print("Fail2ban管理器测试完成")