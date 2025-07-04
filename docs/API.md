# Fail2ban分布式系统 API文档

## 概述

Fail2ban分布式系统提供了完整的RESTful API接口，支持系统监控、IP管理、统计查询等功能。所有API接口都需要通过API密钥进行身份验证。

## 基础信息

- **基础URL**: `http://your-server:5000/api`
- **认证方式**: Bearer Token (API Key)
- **数据格式**: JSON
- **字符编码**: UTF-8

## 认证

所有API请求都需要在请求头中包含API密钥：

```http
Authorization: Bearer your-api-key-here
```

## 通用响应格式

### 成功响应

```json
{
  "success": true,
  "data": {
    // 响应数据
  },
  "message": "操作成功",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 错误响应

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "错误描述",
    "details": "详细错误信息"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## API接口

### 1. 系统状态

#### 1.1 健康检查

**接口**: `GET /health`

**描述**: 检查系统健康状态

**请求参数**: 无

**响应示例**:

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "uptime": 3600,
    "services": {
      "central": "running",
      "database": "connected",
      "cache": "connected"
    }
  }
}
```

#### 1.2 系统统计

**接口**: `GET /stats`

**描述**: 获取系统统计信息

**请求参数**:

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| period | string | 否 | 统计周期: hour, day, week, month |
| format | string | 否 | 返回格式: json, csv |

**响应示例**:

```json
{
  "success": true,
  "data": {
    "total_requests": 150000,
    "total_attacks": 1250,
    "total_bans": 890,
    "active_bans": 45,
    "nodes": {
      "agents": 5,
      "executors": 3,
      "online": 7
    },
    "attack_types": {
      "sql_injection": 450,
      "xss": 320,
      "path_traversal": 280,
      "brute_force": 200
    }
  }
}
```

### 2. IP管理

#### 2.1 获取封禁IP列表

**接口**: `GET /banned-ips`

**描述**: 获取当前封禁的IP列表

**请求参数**:

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| page | integer | 否 | 页码，默认1 |
| limit | integer | 否 | 每页数量，默认50 |
| search | string | 否 | 搜索IP地址 |
| sort | string | 否 | 排序字段: ip, ban_time, unban_time |
| order | string | 否 | 排序方向: asc, desc |

**响应示例**:

```json
{
  "success": true,
  "data": {
    "total": 45,
    "page": 1,
    "limit": 50,
    "items": [
      {
        "ip": "192.168.1.100",
        "ban_time": "2024-01-01T10:00:00Z",
        "unban_time": "2024-01-01T11:00:00Z",
        "reason": "SQL injection attack",
        "attack_count": 15,
        "risk_score": 95,
        "country": "CN",
        "executor_node": "executor-1"
      }
    ]
  }
}
```

#### 2.2 手动封禁IP

**接口**: `POST /ban`

**描述**: 手动封禁指定IP地址

**请求体**:

```json
{
  "ip": "192.168.1.100",
  "duration": 3600,
  "reason": "Manual ban",
  "executor_nodes": ["executor-1", "executor-2"]
}
```

**请求参数**:

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| ip | string | 是 | 要封禁的IP地址 |
| duration | integer | 否 | 封禁时长(秒)，默认3600 |
| reason | string | 否 | 封禁原因 |
| executor_nodes | array | 否 | 指定执行节点，为空则所有节点执行 |

**响应示例**:

```json
{
  "success": true,
  "data": {
    "ip": "192.168.1.100",
    "ban_id": "ban_123456",
    "ban_time": "2024-01-01T10:00:00Z",
    "unban_time": "2024-01-01T11:00:00Z",
    "executed_nodes": ["executor-1", "executor-2"]
  },
  "message": "IP封禁成功"
}
```

#### 2.3 解封IP

**接口**: `POST /unban`

**描述**: 解封指定IP地址

**请求体**:

```json
{
  "ip": "192.168.1.100",
  "reason": "Manual unban"
}
```

**响应示例**:

```json
{
  "success": true,
  "data": {
    "ip": "192.168.1.100",
    "unban_time": "2024-01-01T10:30:00Z",
    "executed_nodes": ["executor-1", "executor-2"]
  },
  "message": "IP解封成功"
}
```

#### 2.4 获取IP详情

**接口**: `GET /ip/{ip}`

**描述**: 获取指定IP的详细信息

**路径参数**:

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| ip | string | 是 | IP地址 |

**响应示例**:

```json
{
  "success": true,
  "data": {
    "ip": "192.168.1.100",
    "status": "banned",
    "first_seen": "2024-01-01T09:00:00Z",
    "last_seen": "2024-01-01T10:00:00Z",
    "total_requests": 150,
    "attack_requests": 25,
    "risk_score": 95,
    "country": "CN",
    "city": "Beijing",
    "isp": "China Telecom",
    "ban_history": [
      {
        "ban_time": "2024-01-01T10:00:00Z",
        "unban_time": "2024-01-01T11:00:00Z",
        "reason": "SQL injection attack",
        "duration": 3600
      }
    ],
    "attack_types": {
      "sql_injection": 15,
      "xss": 8,
      "path_traversal": 2
    },
    "user_agents": [
      "sqlmap/1.0",
      "Mozilla/5.0 (compatible; scanner)"
    ],
    "requested_paths": [
      "/admin.php",
      "/login.php",
      "/wp-admin/"
    ]
  }
}
```

### 3. 节点管理

#### 3.1 获取节点列表

**接口**: `GET /nodes`

**描述**: 获取所有节点状态信息

**响应示例**:

```json
{
  "success": true,
  "data": {
    "total": 8,
    "online": 7,
    "offline": 1,
    "nodes": [
      {
        "id": "agent-1",
        "type": "agent",
        "host": "192.168.1.10",
        "status": "online",
        "last_heartbeat": "2024-01-01T10:00:00Z",
        "version": "1.0.0",
        "uptime": 3600,
        "stats": {
          "processed_logs": 15000,
          "detected_attacks": 125,
          "cpu_usage": 15.5,
          "memory_usage": 128.5
        }
      },
      {
        "id": "executor-1",
        "type": "executor",
        "host": "192.168.1.20",
        "status": "online",
        "last_heartbeat": "2024-01-01T10:00:00Z",
        "version": "1.0.0",
        "uptime": 3600,
        "stats": {
          "executed_bans": 45,
          "executed_unbans": 12,
          "active_bans": 33,
          "cpu_usage": 8.2,
          "memory_usage": 64.3
        }
      }
    ]
  }
}
```

#### 3.2 获取节点详情

**接口**: `GET /nodes/{node_id}`

**描述**: 获取指定节点的详细信息

**路径参数**:

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| node_id | string | 是 | 节点ID |

**响应示例**:

```json
{
  "success": true,
  "data": {
    "id": "agent-1",
    "type": "agent",
    "host": "192.168.1.10",
    "status": "online",
    "registered_time": "2024-01-01T08:00:00Z",
    "last_heartbeat": "2024-01-01T10:00:00Z",
    "version": "1.0.0",
    "uptime": 3600,
    "config": {
      "log_paths": ["/var/log/nginx/access.log"],
      "send_interval": 10,
      "batch_size": 100
    },
    "performance": {
      "cpu_usage": 15.5,
      "memory_usage": 128.5,
      "disk_usage": 45.2,
      "network_io": {
        "bytes_sent": 1048576,
        "bytes_received": 524288
      }
    },
    "statistics": {
      "processed_logs": 15000,
      "detected_attacks": 125,
      "sent_events": 890,
      "errors": 2
    }
  }
}
```

### 4. 攻击分析

#### 4.1 获取最近攻击

**接口**: `GET /attacks`

**描述**: 获取最近检测到的攻击事件

**请求参数**:

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| limit | integer | 否 | 返回数量，默认100 |
| since | string | 否 | 起始时间 (ISO 8601格式) |
| attack_type | string | 否 | 攻击类型过滤 |
| severity | string | 否 | 严重程度: low, medium, high, critical |

**响应示例**:

```json
{
  "success": true,
  "data": {
    "total": 125,
    "attacks": [
      {
        "id": "attack_123456",
        "timestamp": "2024-01-01T10:00:00Z",
        "ip": "192.168.1.100",
        "attack_type": "sql_injection",
        "severity": "high",
        "risk_score": 95,
        "request": {
          "method": "GET",
          "uri": "/admin.php?id=1' union select",
          "user_agent": "sqlmap/1.0",
          "referer": "-"
        },
        "response": {
          "status_code": 404,
          "size": 0
        },
        "detected_patterns": [
          "union_select",
          "sql_comment"
        ],
        "source_node": "agent-1",
        "action_taken": "banned"
      }
    ]
  }
}
```

#### 4.2 攻击统计分析

**接口**: `GET /attacks/stats`

**描述**: 获取攻击统计分析数据

**请求参数**:

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| period | string | 否 | 统计周期: hour, day, week, month |
| group_by | string | 否 | 分组字段: type, ip, country, hour |

**响应示例**:

```json
{
  "success": true,
  "data": {
    "period": "day",
    "total_attacks": 1250,
    "unique_ips": 89,
    "attack_types": {
      "sql_injection": 450,
      "xss": 320,
      "path_traversal": 280,
      "brute_force": 200
    },
    "top_countries": [
      {"country": "CN", "count": 456},
      {"country": "US", "count": 234},
      {"country": "RU", "count": 189}
    ],
    "top_ips": [
      {"ip": "192.168.1.100", "count": 25},
      {"ip": "192.168.1.101", "count": 18},
      {"ip": "192.168.1.102", "count": 15}
    ],
    "hourly_distribution": [
      {"hour": 0, "count": 45},
      {"hour": 1, "count": 38},
      {"hour": 2, "count": 52}
    ]
  }
}
```

### 5. 配置管理

#### 5.1 获取系统配置

**接口**: `GET /config`

**描述**: 获取当前系统配置

**响应示例**:

```json
{
  "success": true,
  "data": {
    "ban_policy": {
      "default_ban_time": 3600,
      "max_ban_time": 86400,
      "risk_threshold": 80,
      "attack_threshold": 5
    },
    "detection": {
      "enabled_types": [
        "sql_injection",
        "xss",
        "path_traversal"
      ],
      "frequency_thresholds": {
        "high_frequency": 100,
        "error_404": 20
      }
    },
    "notifications": {
      "email": {
        "enabled": true,
        "level": "WARNING"
      },
      "dingtalk": {
        "enabled": false
      }
    }
  }
}
```

#### 5.2 更新系统配置

**接口**: `PUT /config`

**描述**: 更新系统配置

**请求体**:

```json
{
  "ban_policy": {
    "default_ban_time": 7200,
    "risk_threshold": 85
  },
  "notifications": {
    "email": {
      "level": "ERROR"
    }
  }
}
```

**响应示例**:

```json
{
  "success": true,
  "data": {
    "updated_fields": [
      "ban_policy.default_ban_time",
      "ban_policy.risk_threshold",
      "notifications.email.level"
    ]
  },
  "message": "配置更新成功"
}
```

### 6. 日志查询

#### 6.1 查询系统日志

**接口**: `GET /logs`

**描述**: 查询系统日志

**请求参数**:

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| level | string | 否 | 日志级别: DEBUG, INFO, WARNING, ERROR |
| since | string | 否 | 起始时间 |
| until | string | 否 | 结束时间 |
| limit | integer | 否 | 返回数量，默认100 |
| search | string | 否 | 搜索关键词 |

**响应示例**:

```json
{
  "success": true,
  "data": {
    "total": 1500,
    "logs": [
      {
        "timestamp": "2024-01-01T10:00:00Z",
        "level": "INFO",
        "component": "central",
        "message": "IP 192.168.1.100 banned for SQL injection attack",
        "details": {
          "ip": "192.168.1.100",
          "attack_type": "sql_injection",
          "ban_duration": 3600
        }
      }
    ]
  }
}
```

## WebSocket API

### 连接信息

- **WebSocket URL**: `ws://your-server:5001/ws`
- **认证**: 连接时需要在查询参数中提供API密钥: `?token=your-api-key`

### 消息格式

#### 客户端发送消息

```json
{
  "type": "subscribe",
  "channels": ["attacks", "bans", "stats"]
}
```

#### 服务端推送消息

```json
{
  "type": "attack",
  "timestamp": "2024-01-01T10:00:00Z",
  "data": {
    "ip": "192.168.1.100",
    "attack_type": "sql_injection",
    "severity": "high",
    "request": {
      "uri": "/admin.php?id=1' union select",
      "user_agent": "sqlmap/1.0"
    }
  }
}
```

### 支持的频道

- `attacks`: 实时攻击事件
- `bans`: IP封禁/解封事件
- `stats`: 统计数据更新
- `nodes`: 节点状态变化
- `alerts`: 系统告警

## 错误代码

| 错误代码 | HTTP状态码 | 描述 |
|----------|------------|------|
| INVALID_API_KEY | 401 | API密钥无效 |
| INSUFFICIENT_PERMISSIONS | 403 | 权限不足 |
| RESOURCE_NOT_FOUND | 404 | 资源不存在 |
| INVALID_PARAMETERS | 400 | 请求参数无效 |
| RATE_LIMIT_EXCEEDED | 429 | 请求频率超限 |
| INTERNAL_ERROR | 500 | 内部服务器错误 |
| SERVICE_UNAVAILABLE | 503 | 服务不可用 |

## 速率限制

- 每个API密钥每分钟最多60个请求
- 批量操作接口每分钟最多10个请求
- WebSocket连接每个IP最多5个并发连接

## SDK和示例

### Python示例

```python
import requests
import json

class Fail2banAPI:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def get_stats(self):
        response = requests.get(
            f'{self.base_url}/api/stats',
            headers=self.headers
        )
        return response.json()
    
    def ban_ip(self, ip, duration=3600, reason='Manual ban'):
        data = {
            'ip': ip,
            'duration': duration,
            'reason': reason
        }
        response = requests.post(
            f'{self.base_url}/api/ban',
            headers=self.headers,
            json=data
        )
        return response.json()
    
    def get_banned_ips(self, page=1, limit=50):
        params = {'page': page, 'limit': limit}
        response = requests.get(
            f'{self.base_url}/api/banned-ips',
            headers=self.headers,
            params=params
        )
        return response.json()

# 使用示例
api = Fail2banAPI('http://localhost:5000', 'your-api-key')

# 获取统计信息
stats = api.get_stats()
print(f"总攻击数: {stats['data']['total_attacks']}")

# 封禁IP
result = api.ban_ip('192.168.1.100', 7200, 'Suspicious activity')
print(f"封禁结果: {result['message']}")

# 获取封禁列表
banned = api.get_banned_ips()
print(f"当前封禁IP数量: {banned['data']['total']}")
```

### JavaScript示例

```javascript
class Fail2banAPI {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        };
    }
    
    async getStats() {
        const response = await fetch(`${this.baseUrl}/api/stats`, {
            headers: this.headers
        });
        return await response.json();
    }
    
    async banIP(ip, duration = 3600, reason = 'Manual ban') {
        const response = await fetch(`${this.baseUrl}/api/ban`, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify({ ip, duration, reason })
        });
        return await response.json();
    }
    
    // WebSocket连接
    connectWebSocket() {
        const ws = new WebSocket(`ws://localhost:5001/ws?token=${this.apiKey}`);
        
        ws.onopen = () => {
            console.log('WebSocket连接已建立');
            // 订阅攻击事件
            ws.send(JSON.stringify({
                type: 'subscribe',
                channels: ['attacks', 'bans']
            }));
        };
        
        ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            console.log('收到消息:', message);
        };
        
        return ws;
    }
}

// 使用示例
const api = new Fail2banAPI('http://localhost:5000', 'your-api-key');

// 获取统计信息
api.getStats().then(stats => {
    console.log(`总攻击数: ${stats.data.total_attacks}`);
});

// 建立WebSocket连接
const ws = api.connectWebSocket();
```

## 更新日志

### v1.0.0 (2024-01-01)

- 初始版本发布
- 支持基础的IP管理、统计查询、节点管理功能
- 提供WebSocket实时推送
- 完整的认证和权限控制

---

如有问题或建议，请联系技术支持团队。