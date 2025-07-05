#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库工具模块
提供Redis和MongoDB的连接池管理、错误处理和性能优化
"""

import asyncio
import time
import logging
from typing import Optional, Dict, Any, List, Union
from contextlib import asynccontextmanager
from dataclasses import dataclass

try:
    import redis
    from redis.asyncio import Redis as AsyncRedis
    from redis.asyncio.connection import ConnectionPool as AsyncConnectionPool
except ImportError:
    redis = None
    AsyncRedis = None
    AsyncConnectionPool = None

try:
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
    from pymongo.errors import PyMongoError, ConnectionFailure, ServerSelectionTimeoutError
except ImportError:
    AsyncIOMotorClient = None
    AsyncIOMotorDatabase = None
    PyMongoError = None
    ConnectionFailure = None
    ServerSelectionTimeoutError = None


class DatabaseError(Exception):
    """数据库基础异常"""
    pass


class ConnectionError(DatabaseError):
    """数据库连接异常"""
    pass


class OperationError(DatabaseError):
    """数据库操作异常"""
    pass


class PoolExhaustedError(DatabaseError):
    """连接池耗尽异常"""
    pass


@dataclass
class DatabaseStats:
    """数据库统计信息"""
    connection_count: int = 0
    active_connections: int = 0
    total_operations: int = 0
    failed_operations: int = 0
    avg_response_time: float = 0.0
    last_error: Optional[str] = None
    uptime: float = 0.0


class RedisManager:
    """Redis连接管理器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("redis_manager")
        self.pool: Optional[AsyncConnectionPool] = None
        self.client: Optional[AsyncRedis] = None
        self.stats = DatabaseStats()
        self._start_time = time.time()
        
        if not redis:
            raise ImportError("Redis库未安装，请运行: pip install redis")
    
    async def initialize(self) -> None:
        """初始化Redis连接池"""
        try:
            redis_config = self.config.get('redis', {})
            
            # 创建连接池
            self.pool = AsyncConnectionPool(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                password=redis_config.get('password'),
                db=redis_config.get('db', 0),
                max_connections=redis_config.get('max_connections', 100),
                socket_timeout=redis_config.get('socket_timeout', 5),
                socket_connect_timeout=redis_config.get('socket_connect_timeout', 5),
                retry_on_timeout=redis_config.get('retry_on_timeout', True),
                health_check_interval=redis_config.get('health_check_interval', 30)
            )
            
            # 创建客户端
            self.client = AsyncRedis(connection_pool=self.pool)
            
            # 测试连接
            await self.client.ping()
            self.logger.info("Redis连接池初始化成功")
            
        except Exception as e:
            self.logger.error(f"Redis连接池初始化失败: {e}")
            raise ConnectionError(f"Redis连接失败: {e}")
    
    async def close(self) -> None:
        """关闭Redis连接"""
        if self.client:
            await self.client.close()
        if self.pool:
            await self.pool.disconnect()
        self.logger.info("Redis连接已关闭")
    
    @asynccontextmanager
    async def get_connection(self):
        """获取Redis连接的上下文管理器"""
        if not self.client:
            raise ConnectionError("Redis未初始化")
        
        start_time = time.time()
        try:
            self.stats.active_connections += 1
            yield self.client
            self.stats.total_operations += 1
        except Exception as e:
            self.stats.failed_operations += 1
            self.stats.last_error = str(e)
            self.logger.error(f"Redis操作失败: {e}")
            raise OperationError(f"Redis操作失败: {e}")
        finally:
            self.stats.active_connections -= 1
            response_time = time.time() - start_time
            self.stats.avg_response_time = (
                (self.stats.avg_response_time * (self.stats.total_operations - 1) + response_time) /
                self.stats.total_operations if self.stats.total_operations > 0 else 0
            )
    
    async def set_with_retry(self, key: str, value: Any, ex: Optional[int] = None, retries: int = 3) -> bool:
        """带重试的设置操作"""
        for attempt in range(retries):
            try:
                async with self.get_connection() as conn:
                    return await conn.set(key, value, ex=ex)
            except Exception as e:
                if attempt == retries - 1:
                    raise
                await asyncio.sleep(0.1 * (attempt + 1))
        return False
    
    async def get_with_retry(self, key: str, retries: int = 3) -> Optional[Any]:
        """带重试的获取操作"""
        for attempt in range(retries):
            try:
                async with self.get_connection() as conn:
                    return await conn.get(key)
            except Exception as e:
                if attempt == retries - 1:
                    raise
                await asyncio.sleep(0.1 * (attempt + 1))
        return None
    
    async def pipeline_execute(self, operations: List[tuple]) -> List[Any]:
        """批量执行Redis操作"""
        async with self.get_connection() as conn:
            pipe = conn.pipeline()
            for op, args in operations:
                getattr(pipe, op)(*args)
            return await pipe.execute()
    
    def get_stats(self) -> DatabaseStats:
        """获取统计信息"""
        self.stats.uptime = time.time() - self._start_time
        self.stats.connection_count = self.pool.created_connections if self.pool else 0
        return self.stats


class MongoManager:
    """MongoDB连接管理器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("mongo_manager")
        self.client: Optional[AsyncIOMotorClient] = None
        self.database: Optional[AsyncIOMotorDatabase] = None
        self.stats = DatabaseStats()
        self._start_time = time.time()
        
        if not AsyncIOMotorClient:
            raise ImportError("Motor库未安装，请运行: pip install motor")
    
    async def initialize(self) -> None:
        """初始化MongoDB连接"""
        try:
            mongo_config = self.config.get('mongodb', {})
            
            # 构建连接字符串
            host = mongo_config.get('host', 'localhost')
            port = mongo_config.get('port', 27017)
            username = mongo_config.get('username')
            password = mongo_config.get('password')
            
            if username and password:
                connection_string = f"mongodb://{username}:{password}@{host}:{port}"
            else:
                connection_string = f"mongodb://{host}:{port}"
            
            # 创建客户端
            self.client = AsyncIOMotorClient(
                connection_string,
                maxPoolSize=mongo_config.get('max_pool_size', 50),
                minPoolSize=mongo_config.get('min_pool_size', 5),
                maxIdleTimeMS=mongo_config.get('max_idle_time_ms', 30000),
                serverSelectionTimeoutMS=mongo_config.get('server_selection_timeout_ms', 5000),
                connectTimeoutMS=mongo_config.get('connect_timeout_ms', 5000),
                socketTimeoutMS=mongo_config.get('socket_timeout_ms', 5000)
            )
            
            # 获取数据库
            db_name = mongo_config.get('database', 'fail2ban')
            self.database = self.client[db_name]
            
            # 测试连接
            await self.client.admin.command('ping')
            self.logger.info("MongoDB连接初始化成功")
            
        except Exception as e:
            self.logger.error(f"MongoDB连接初始化失败: {e}")
            raise ConnectionError(f"MongoDB连接失败: {e}")
    
    async def close(self) -> None:
        """关闭MongoDB连接"""
        if self.client:
            self.client.close()
        self.logger.info("MongoDB连接已关闭")
    
    @asynccontextmanager
    async def get_collection(self, collection_name: str):
        """获取MongoDB集合的上下文管理器"""
        if not self.database:
            raise ConnectionError("MongoDB未初始化")
        
        start_time = time.time()
        try:
            self.stats.active_connections += 1
            yield self.database[collection_name]
            self.stats.total_operations += 1
        except Exception as e:
            self.stats.failed_operations += 1
            self.stats.last_error = str(e)
            self.logger.error(f"MongoDB操作失败: {e}")
            raise OperationError(f"MongoDB操作失败: {e}")
        finally:
            self.stats.active_connections -= 1
            response_time = time.time() - start_time
            self.stats.avg_response_time = (
                (self.stats.avg_response_time * (self.stats.total_operations - 1) + response_time) /
                self.stats.total_operations if self.stats.total_operations > 0 else 0
            )
    
    async def insert_with_retry(self, collection_name: str, document: Dict[str, Any], retries: int = 3) -> Any:
        """带重试的插入操作"""
        for attempt in range(retries):
            try:
                async with self.get_collection(collection_name) as collection:
                    return await collection.insert_one(document)
            except Exception as e:
                if attempt == retries - 1:
                    raise
                await asyncio.sleep(0.1 * (attempt + 1))
    
    async def find_with_retry(self, collection_name: str, query: Dict[str, Any], retries: int = 3) -> List[Dict[str, Any]]:
        """带重试的查询操作"""
        for attempt in range(retries):
            try:
                async with self.get_collection(collection_name) as collection:
                    cursor = collection.find(query)
                    return await cursor.to_list(length=None)
            except Exception as e:
                if attempt == retries - 1:
                    raise
                await asyncio.sleep(0.1 * (attempt + 1))
        return []
    
    async def bulk_insert(self, collection_name: str, documents: List[Dict[str, Any]]) -> Any:
        """批量插入文档"""
        async with self.get_collection(collection_name) as collection:
            return await collection.insert_many(documents)
    
    async def create_indexes(self, collection_name: str, indexes: List[tuple]) -> None:
        """创建索引"""
        async with self.get_collection(collection_name) as collection:
            for index_spec, index_options in indexes:
                await collection.create_index(index_spec, **index_options)
    
    def get_stats(self) -> DatabaseStats:
        """获取统计信息"""
        self.stats.uptime = time.time() - self._start_time
        return self.stats


class DatabaseManager:
    """数据库管理器 - 统一管理Redis和MongoDB"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("database_manager")
        
        # 初始化管理器
        self.redis_manager: Optional[RedisManager] = None
        self.mongo_manager: Optional[MongoManager] = None
        
        # 根据配置初始化相应的管理器
        db_config = config.get('central', {}).get('database', {})
        
        if 'redis' in db_config:
            self.redis_manager = RedisManager(db_config)
        
        if 'mongodb' in db_config:
            self.mongo_manager = MongoManager(db_config)
    
    async def initialize(self) -> None:
        """初始化所有数据库连接"""
        tasks = []
        
        if self.redis_manager:
            tasks.append(self.redis_manager.initialize())
        
        if self.mongo_manager:
            tasks.append(self.mongo_manager.initialize())
        
        if tasks:
            await asyncio.gather(*tasks)
            self.logger.info("所有数据库连接初始化完成")
        else:
            self.logger.warning("未配置任何数据库")
    
    async def close(self) -> None:
        """关闭所有数据库连接"""
        tasks = []
        
        if self.redis_manager:
            tasks.append(self.redis_manager.close())
        
        if self.mongo_manager:
            tasks.append(self.mongo_manager.close())
        
        if tasks:
            await asyncio.gather(*tasks)
            self.logger.info("所有数据库连接已关闭")
    
    def get_redis(self) -> Optional[RedisManager]:
        """获取Redis管理器"""
        return self.redis_manager
    
    def get_mongo(self) -> Optional[MongoManager]:
        """获取MongoDB管理器"""
        return self.mongo_manager
    
    async def health_check(self) -> Dict[str, Any]:
        """健康检查"""
        health_status = {
            'redis': {'status': 'disabled', 'stats': None},
            'mongodb': {'status': 'disabled', 'stats': None}
        }
        
        # Redis健康检查
        if self.redis_manager:
            try:
                async with self.redis_manager.get_connection() as conn:
                    await conn.ping()
                health_status['redis']['status'] = 'healthy'
                health_status['redis']['stats'] = self.redis_manager.get_stats().__dict__
            except Exception as e:
                health_status['redis']['status'] = 'unhealthy'
                health_status['redis']['error'] = str(e)
        
        # MongoDB健康检查
        if self.mongo_manager:
            try:
                if self.mongo_manager.client:
                    await self.mongo_manager.client.admin.command('ping')
                health_status['mongodb']['status'] = 'healthy'
                health_status['mongodb']['stats'] = self.mongo_manager.get_stats().__dict__
            except Exception as e:
                health_status['mongodb']['status'] = 'unhealthy'
                health_status['mongodb']['error'] = str(e)
        
        return health_status


# 工具函数
def hash_ip(ip: str) -> str:
    """IP地址哈希函数"""
    import hashlib
    return hashlib.md5(ip.encode()).hexdigest()[:16]


async def test_database_connections(config: Dict[str, Any]) -> None:
    """测试数据库连接"""
    db_manager = DatabaseManager(config)
    
    try:
        await db_manager.initialize()
        health = await db_manager.health_check()
        
        print("数据库连接测试结果:")
        for db_type, status in health.items():
            print(f"  {db_type}: {status['status']}")
            if 'stats' in status and status['stats']:
                stats = status['stats']
                print(f"    - 总操作数: {stats['total_operations']}")
                print(f"    - 失败操作数: {stats['failed_operations']}")
                print(f"    - 平均响应时间: {stats['avg_response_time']:.3f}s")
    
    except Exception as e:
        print(f"数据库连接测试失败: {e}")
    
    finally:
        await db_manager.close()


if __name__ == "__main__":
    # 测试配置
    test_config = {
        'central': {
            'database': {
                'redis': {
                    'host': 'localhost',
                    'port': 6379,
                    'db': 0,
                    'max_connections': 10
                },
                'mongodb': {
                    'host': 'localhost',
                    'port': 27017,
                    'database': 'test_fail2ban',
                    'max_pool_size': 10
                }
            }
        }
    }
    
    # 运行测试
    asyncio.run(test_database_connections(test_config))