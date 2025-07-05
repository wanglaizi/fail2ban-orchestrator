#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 机器学习攻击检测

实现基于机器学习的高级攻击检测和行为分析
"""

import asyncio
import json
import logging
import pickle
import numpy as np
import pandas as pd
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import joblib
import re
from urllib.parse import unquote

# 机器学习库
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline

# 深度学习（可选）
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Dense, LSTM, Embedding, Dropout
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logging.warning("TensorFlow未安装，深度学习功能将不可用")


@dataclass
class AttackPattern:
    """攻击模式"""
    pattern_id: str
    attack_type: str
    pattern: str
    confidence: float
    description: str
    examples: List[str]
    created_at: datetime
    updated_at: datetime


@dataclass
class MLPrediction:
    """机器学习预测结果"""
    is_attack: bool
    attack_type: Optional[str]
    confidence: float
    probability_scores: Dict[str, float]
    feature_importance: Dict[str, float]
    model_name: str
    prediction_time: datetime


class FeatureExtractor:
    """特征提取器"""
    
    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            analyzer='char',
            lowercase=True
        )
        self.url_vectorizer = TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 2),
            analyzer='word',
            token_pattern=r'[^/\s]+'
        )
        self.is_fitted = False
        
        # 攻击特征模式
        self.attack_keywords = {
            'sql_injection': [
                'union', 'select', 'insert', 'delete', 'update', 'drop', 'create',
                'alter', 'exec', 'execute', 'sp_', 'xp_', 'waitfor', 'delay',
                'benchmark', 'sleep', 'pg_sleep', 'information_schema', 'sysobjects'
            ],
            'xss': [
                'script', 'javascript', 'vbscript', 'onload', 'onerror', 'onclick',
                'onmouseover', 'onfocus', 'onblur', 'alert', 'confirm', 'prompt',
                'document.cookie', 'window.location', 'eval', 'fromcharcode'
            ],
            'command_injection': [
                'cat', 'ls', 'pwd', 'whoami', 'id', 'uname', 'ps', 'netstat',
                'ifconfig', 'rm', 'mv', 'cp', 'chmod', 'chown', 'kill', 'killall',
                'wget', 'curl', 'nc', 'telnet', 'ssh', 'ftp'
            ],
            'directory_traversal': [
                '../', '..\\', '%2e%2e%2f', '%2e%2e%5c', '....///', '....\\\\',
                '/etc/passwd', '/etc/shadow', '/windows/system32', 'boot.ini'
            ],
            'file_inclusion': [
                'php://filter', 'php://input', 'data://', 'file://', 'ftp://',
                'http://', 'https://', 'expect://', 'zip://', 'phar://'
            ]
        }
        
        # 编译正则表达式
        self.compiled_patterns = {}
        for attack_type, keywords in self.attack_keywords.items():
            patterns = [re.escape(keyword) for keyword in keywords]
            self.compiled_patterns[attack_type] = re.compile(
                '|'.join(patterns), re.IGNORECASE
            )
    
    def extract_basic_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """提取基础特征
        
        Args:
            request_data: 请求数据
            
        Returns:
            特征字典
        """
        features = {}
        
        # URL特征
        url = request_data.get('url', '')
        features['url_length'] = len(url)
        features['url_params_count'] = url.count('&')
        features['url_special_chars'] = sum(1 for c in url if c in '!@#$%^&*()+={}[]|\\:;"<>?')
        features['url_encoded_chars'] = url.count('%')
        features['url_dots'] = url.count('.')
        features['url_slashes'] = url.count('/')
        features['url_question_marks'] = url.count('?')
        
        # 请求体特征
        body = request_data.get('body', '')
        features['body_length'] = len(body)
        features['body_special_chars'] = sum(1 for c in body if c in '!@#$%^&*()+={}[]|\\:;"<>?')
        features['body_encoded_chars'] = body.count('%')
        
        # HTTP方法特征
        method = request_data.get('method', 'GET')
        features['method_get'] = 1.0 if method == 'GET' else 0.0
        features['method_post'] = 1.0 if method == 'POST' else 0.0
        features['method_put'] = 1.0 if method == 'PUT' else 0.0
        features['method_delete'] = 1.0 if method == 'DELETE' else 0.0
        features['method_other'] = 1.0 if method not in ['GET', 'POST', 'PUT', 'DELETE'] else 0.0
        
        # User-Agent特征
        user_agent = request_data.get('user_agent', '')
        features['ua_length'] = len(user_agent)
        features['ua_is_bot'] = 1.0 if any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider']) else 0.0
        features['ua_is_empty'] = 1.0 if not user_agent else 0.0
        
        # 时间特征
        timestamp = request_data.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        features['hour'] = timestamp.hour
        features['day_of_week'] = timestamp.weekday()
        features['is_weekend'] = 1.0 if timestamp.weekday() >= 5 else 0.0
        features['is_night'] = 1.0 if timestamp.hour < 6 or timestamp.hour > 22 else 0.0
        
        # 响应特征
        features['response_status'] = request_data.get('response_status', 200)
        features['response_size'] = request_data.get('response_size', 0)
        features['response_time'] = request_data.get('response_time', 0)
        
        return features
    
    def extract_attack_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """提取攻击特征
        
        Args:
            request_data: 请求数据
            
        Returns:
            攻击特征字典
        """
        features = {}
        
        # 合并URL和请求体进行分析
        text_content = f"{request_data.get('url', '')} {request_data.get('body', '')}"
        text_content = unquote(text_content.lower())
        
        # 检测各种攻击模式
        for attack_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text_content)
            features[f'{attack_type}_keyword_count'] = len(matches)
            features[f'{attack_type}_detected'] = 1.0 if matches else 0.0
        
        # SQL注入特征
        features['sql_quotes'] = text_content.count("'") + text_content.count('"')
        features['sql_comments'] = text_content.count('--') + text_content.count('/*')
        features['sql_semicolons'] = text_content.count(';')
        features['sql_unions'] = text_content.count('union')
        
        # XSS特征
        features['xss_script_tags'] = text_content.count('<script')
        features['xss_event_handlers'] = sum(1 for event in ['onload', 'onerror', 'onclick'] if event in text_content)
        features['xss_javascript'] = text_content.count('javascript:')
        
        # 目录遍历特征
        features['dir_traversal_dots'] = text_content.count('../') + text_content.count('..\\')
        features['dir_traversal_encoded'] = text_content.count('%2e%2e')
        
        # 命令注入特征
        features['cmd_injection_pipes'] = text_content.count('|') + text_content.count('&')
        features['cmd_injection_backticks'] = text_content.count('`')
        features['cmd_injection_dollar'] = text_content.count('$(')
        
        # 文件包含特征
        features['file_inclusion_protocols'] = sum(1 for proto in ['php://', 'file://', 'data://'] if proto in text_content)
        
        return features
    
    def extract_behavioral_features(self, ip_history: List[Dict[str, Any]]) -> Dict[str, float]:
        """提取行为特征
        
        Args:
            ip_history: IP历史记录
            
        Returns:
            行为特征字典
        """
        features = {}
        
        if not ip_history:
            return {f'behavior_{key}': 0.0 for key in [
                'request_rate', 'error_rate', 'unique_paths', 'unique_user_agents',
                'avg_response_time', 'night_requests_ratio', 'weekend_requests_ratio'
            ]}
        
        # 计算时间窗口
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        recent_requests = [
            req for req in ip_history 
            if datetime.fromisoformat(req.get('timestamp', now.isoformat())) >= hour_ago
        ]
        
        if not recent_requests:
            return {f'behavior_{key}': 0.0 for key in [
                'request_rate', 'error_rate', 'unique_paths', 'unique_user_agents',
                'avg_response_time', 'night_requests_ratio', 'weekend_requests_ratio'
            ]}
        
        # 请求频率
        features['behavior_request_rate'] = len(recent_requests) / 3600  # 每秒请求数
        
        # 错误率
        error_requests = [req for req in recent_requests if req.get('response_status', 200) >= 400]
        features['behavior_error_rate'] = len(error_requests) / len(recent_requests)
        
        # 唯一路径数
        unique_paths = set(req.get('url', '') for req in recent_requests)
        features['behavior_unique_paths'] = len(unique_paths)
        
        # 唯一User-Agent数
        unique_user_agents = set(req.get('user_agent', '') for req in recent_requests)
        features['behavior_unique_user_agents'] = len(unique_user_agents)
        
        # 平均响应时间
        response_times = [req.get('response_time', 0) for req in recent_requests if req.get('response_time')]
        features['behavior_avg_response_time'] = np.mean(response_times) if response_times else 0
        
        # 夜间请求比例
        night_requests = [
            req for req in recent_requests 
            if datetime.fromisoformat(req.get('timestamp', now.isoformat())).hour < 6 or 
               datetime.fromisoformat(req.get('timestamp', now.isoformat())).hour > 22
        ]
        features['behavior_night_requests_ratio'] = len(night_requests) / len(recent_requests)
        
        # 周末请求比例
        weekend_requests = [
            req for req in recent_requests 
            if datetime.fromisoformat(req.get('timestamp', now.isoformat())).weekday() >= 5
        ]
        features['behavior_weekend_requests_ratio'] = len(weekend_requests) / len(recent_requests)
        
        return features
    
    def extract_text_features(self, text_data: List[str]) -> np.ndarray:
        """提取文本特征
        
        Args:
            text_data: 文本数据列表
            
        Returns:
            文本特征矩阵
        """
        if not self.is_fitted:
            # 拟合TF-IDF向量化器
            self.tfidf_vectorizer.fit(text_data)
            self.is_fitted = True
        
        return self.tfidf_vectorizer.transform(text_data).toarray()
    
    def extract_all_features(self, request_data: Dict[str, Any], 
                           ip_history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, float]:
        """提取所有特征
        
        Args:
            request_data: 请求数据
            ip_history: IP历史记录
            
        Returns:
            完整特征字典
        """
        features = {}
        
        # 基础特征
        features.update(self.extract_basic_features(request_data))
        
        # 攻击特征
        features.update(self.extract_attack_features(request_data))
        
        # 行为特征
        if ip_history:
            features.update(self.extract_behavioral_features(ip_history))
        
        return features


class MLModel:
    """机器学习模型基类"""
    
    def __init__(self, model_name: str, model_type: str = 'classification'):
        self.model_name = model_name
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        self.feature_names = []
        self.training_history = []
        
    def prepare_data(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """准备训练数据
        
        Args:
            X: 特征矩阵
            y: 标签向量
            
        Returns:
            处理后的特征矩阵和标签向量
        """
        # 标准化特征
        if not self.is_trained:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)
        
        # 编码标签
        y_encoded = None
        if y is not None:
            if not self.is_trained:
                y_encoded = self.label_encoder.fit_transform(y)
            else:
                y_encoded = self.label_encoder.transform(y)
        
        return X_scaled, y_encoded
    
    def train(self, X: np.ndarray, y: np.ndarray, validation_split: float = 0.2) -> Dict[str, Any]:
        """训练模型
        
        Args:
            X: 特征矩阵
            y: 标签向量
            validation_split: 验证集比例
            
        Returns:
            训练结果
        """
        raise NotImplementedError
    
    def predict(self, X: np.ndarray) -> MLPrediction:
        """预测
        
        Args:
            X: 特征矩阵
            
        Returns:
            预测结果
        """
        raise NotImplementedError
    
    def save_model(self, filepath: str) -> None:
        """保存模型
        
        Args:
            filepath: 文件路径
        """
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names,
            'model_name': self.model_name,
            'model_type': self.model_type
        }
        
        joblib.dump(model_data, filepath)
    
    def load_model(self, filepath: str) -> None:
        """加载模型
        
        Args:
            filepath: 文件路径
        """
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.label_encoder = model_data['label_encoder']
        self.is_trained = model_data['is_trained']
        self.feature_names = model_data['feature_names']
        self.model_name = model_data['model_name']
        self.model_type = model_data['model_type']


class RandomForestModel(MLModel):
    """随机森林模型"""
    
    def __init__(self):
        super().__init__('RandomForest', 'classification')
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
    
    def train(self, X: np.ndarray, y: np.ndarray, validation_split: float = 0.2) -> Dict[str, Any]:
        """训练随机森林模型"""
        X_scaled, y_encoded = self.prepare_data(X, y)
        
        # 分割训练和验证集
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y_encoded, test_size=validation_split, random_state=42, stratify=y_encoded
        )
        
        # 训练模型
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # 验证模型
        train_score = self.model.score(X_train, y_train)
        val_score = self.model.score(X_val, y_val)
        
        # 交叉验证
        cv_scores = cross_val_score(self.model, X_scaled, y_encoded, cv=5)
        
        # 预测验证集
        y_pred = self.model.predict(X_val)
        y_pred_proba = self.model.predict_proba(X_val)
        
        # 计算AUC（如果是二分类）
        auc_score = None
        if len(np.unique(y_encoded)) == 2:
            auc_score = roc_auc_score(y_val, y_pred_proba[:, 1])
        
        training_result = {
            'train_accuracy': train_score,
            'validation_accuracy': val_score,
            'cv_mean_accuracy': cv_scores.mean(),
            'cv_std_accuracy': cv_scores.std(),
            'auc_score': auc_score,
            'feature_importance': dict(zip(self.feature_names, self.model.feature_importances_)),
            'classification_report': classification_report(y_val, y_pred, output_dict=True)
        }
        
        self.training_history.append(training_result)
        return training_result
    
    def predict(self, X: np.ndarray) -> MLPrediction:
        """预测"""
        if not self.is_trained:
            raise ValueError("模型尚未训练")
        
        X_scaled, _ = self.prepare_data(X)
        
        # 预测
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        # 获取类别名称
        class_names = self.label_encoder.classes_
        
        # 构建预测结果
        prediction = predictions[0]
        probability_scores = dict(zip(class_names, probabilities[0]))
        
        is_attack = prediction != 'normal' if 'normal' in class_names else prediction == 1
        attack_type = self.label_encoder.inverse_transform([prediction])[0] if is_attack else None
        confidence = max(probabilities[0])
        
        # 特征重要性
        feature_importance = dict(zip(self.feature_names, self.model.feature_importances_))
        
        return MLPrediction(
            is_attack=is_attack,
            attack_type=attack_type,
            confidence=confidence,
            probability_scores=probability_scores,
            feature_importance=feature_importance,
            model_name=self.model_name,
            prediction_time=datetime.now()
        )


class AnomalyDetectionModel(MLModel):
    """异常检测模型"""
    
    def __init__(self):
        super().__init__('IsolationForest', 'anomaly_detection')
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
    
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None, validation_split: float = 0.2) -> Dict[str, Any]:
        """训练异常检测模型"""
        X_scaled, _ = self.prepare_data(X)
        
        # 训练模型（无监督学习）
        self.model.fit(X_scaled)
        self.is_trained = True
        
        # 预测训练数据
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.decision_function(X_scaled)
        
        # 计算异常比例
        anomaly_ratio = np.sum(predictions == -1) / len(predictions)
        
        training_result = {
            'anomaly_ratio': anomaly_ratio,
            'mean_anomaly_score': np.mean(anomaly_scores),
            'std_anomaly_score': np.std(anomaly_scores),
            'min_anomaly_score': np.min(anomaly_scores),
            'max_anomaly_score': np.max(anomaly_scores)
        }
        
        self.training_history.append(training_result)
        return training_result
    
    def predict(self, X: np.ndarray) -> MLPrediction:
        """预测异常"""
        if not self.is_trained:
            raise ValueError("模型尚未训练")
        
        X_scaled, _ = self.prepare_data(X)
        
        # 预测
        prediction = self.model.predict(X_scaled)[0]
        anomaly_score = self.model.decision_function(X_scaled)[0]
        
        is_attack = prediction == -1
        confidence = abs(anomaly_score)
        
        return MLPrediction(
            is_attack=is_attack,
            attack_type='anomaly' if is_attack else None,
            confidence=confidence,
            probability_scores={'anomaly': confidence, 'normal': 1 - confidence},
            feature_importance={},
            model_name=self.model_name,
            prediction_time=datetime.now()
        )


class DeepLearningModel(MLModel):
    """深度学习模型"""
    
    def __init__(self):
        super().__init__('DeepLearning', 'classification')
        self.model = None
        self.tokenizer = None
        self.max_sequence_length = 100
        
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow未安装，无法使用深度学习模型")
    
    def build_model(self, input_dim: int, num_classes: int) -> None:
        """构建深度学习模型
        
        Args:
            input_dim: 输入维度
            num_classes: 类别数量
        """
        self.model = Sequential([
            Dense(256, activation='relu', input_shape=(input_dim,)),
            Dropout(0.3),
            Dense(128, activation='relu'),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.2),
            Dense(num_classes, activation='softmax' if num_classes > 2 else 'sigmoid')
        ])
        
        self.model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy' if num_classes > 2 else 'binary_crossentropy',
            metrics=['accuracy']
        )
    
    def train(self, X: np.ndarray, y: np.ndarray, validation_split: float = 0.2) -> Dict[str, Any]:
        """训练深度学习模型"""
        X_scaled, y_encoded = self.prepare_data(X, y)
        
        # 构建模型
        num_classes = len(np.unique(y_encoded))
        self.build_model(X_scaled.shape[1], num_classes)
        
        # 训练模型
        history = self.model.fit(
            X_scaled, y_encoded,
            validation_split=validation_split,
            epochs=50,
            batch_size=32,
            verbose=0
        )
        
        self.is_trained = True
        
        # 获取训练历史
        training_result = {
            'final_train_accuracy': history.history['accuracy'][-1],
            'final_val_accuracy': history.history['val_accuracy'][-1],
            'final_train_loss': history.history['loss'][-1],
            'final_val_loss': history.history['val_loss'][-1],
            'training_history': history.history
        }
        
        self.training_history.append(training_result)
        return training_result
    
    def predict(self, X: np.ndarray) -> MLPrediction:
        """预测"""
        if not self.is_trained:
            raise ValueError("模型尚未训练")
        
        X_scaled, _ = self.prepare_data(X)
        
        # 预测
        probabilities = self.model.predict(X_scaled, verbose=0)[0]
        prediction = np.argmax(probabilities)
        
        # 获取类别名称
        class_names = self.label_encoder.classes_
        probability_scores = dict(zip(class_names, probabilities))
        
        is_attack = prediction != 0 if len(class_names) > 2 else prediction == 1
        attack_type = class_names[prediction] if is_attack else None
        confidence = max(probabilities)
        
        return MLPrediction(
            is_attack=is_attack,
            attack_type=attack_type,
            confidence=confidence,
            probability_scores=probability_scores,
            feature_importance={},
            model_name=self.model_name,
            prediction_time=datetime.now()
        )


class EnsembleModel:
    """集成模型"""
    
    def __init__(self, models: List[MLModel]):
        self.models = models
        self.weights = [1.0] * len(models)  # 等权重
        self.is_trained = False
    
    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """训练所有模型"""
        training_results = {}
        
        for i, model in enumerate(self.models):
            try:
                result = model.train(X, y)
                training_results[model.model_name] = result
                
                # 根据验证准确率调整权重
                if 'validation_accuracy' in result:
                    self.weights[i] = result['validation_accuracy']
                elif 'final_val_accuracy' in result:
                    self.weights[i] = result['final_val_accuracy']
                    
            except Exception as e:
                logging.error(f"训练模型 {model.model_name} 时发生错误: {e}")
                self.weights[i] = 0.0
        
        # 归一化权重
        total_weight = sum(self.weights)
        if total_weight > 0:
            self.weights = [w / total_weight for w in self.weights]
        
        self.is_trained = True
        return training_results
    
    def predict(self, X: np.ndarray) -> MLPrediction:
        """集成预测"""
        if not self.is_trained:
            raise ValueError("模型尚未训练")
        
        predictions = []
        total_weight = 0
        
        for model, weight in zip(self.models, self.weights):
            if weight > 0:
                try:
                    pred = model.predict(X)
                    predictions.append((pred, weight))
                    total_weight += weight
                except Exception as e:
                    logging.error(f"模型 {model.model_name} 预测时发生错误: {e}")
        
        if not predictions:
            raise ValueError("没有可用的模型进行预测")
        
        # 加权投票
        weighted_attack_votes = 0
        weighted_confidence = 0
        attack_types = defaultdict(float)
        all_probability_scores = defaultdict(float)
        
        for pred, weight in predictions:
            if pred.is_attack:
                weighted_attack_votes += weight
                if pred.attack_type:
                    attack_types[pred.attack_type] += weight
            
            weighted_confidence += pred.confidence * weight
            
            for class_name, prob in pred.probability_scores.items():
                all_probability_scores[class_name] += prob * weight
        
        # 最终决策
        is_attack = weighted_attack_votes > (total_weight / 2)
        attack_type = max(attack_types.items(), key=lambda x: x[1])[0] if attack_types else None
        confidence = weighted_confidence / total_weight
        
        # 归一化概率分数
        total_prob = sum(all_probability_scores.values())
        if total_prob > 0:
            probability_scores = {k: v / total_prob for k, v in all_probability_scores.items()}
        else:
            probability_scores = dict(all_probability_scores)
        
        return MLPrediction(
            is_attack=is_attack,
            attack_type=attack_type,
            confidence=confidence,
            probability_scores=probability_scores,
            feature_importance={},
            model_name='Ensemble',
            prediction_time=datetime.now()
        )


class MLAttackDetectionSystem:
    """机器学习攻击检测系统"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.feature_extractor = FeatureExtractor()
        self.models = {}
        self.ensemble_model = None
        self.training_data = deque(maxlen=10000)
        self.prediction_cache = deque(maxlen=1000)
        self.logger = logging.getLogger(__name__)
        
        # 模型配置
        self.model_config = config.get('ml_models', {
            'random_forest': True,
            'anomaly_detection': True,
            'deep_learning': False  # 默认关闭深度学习
        })
        
        # 初始化模型
        self._initialize_models()
        
        # 自动训练配置
        self.auto_retrain = config.get('auto_retrain', True)
        self.retrain_threshold = config.get('retrain_threshold', 1000)  # 新数据达到阈值时重新训练
        self.retrain_interval = config.get('retrain_interval', 86400)  # 24小时
        self.last_training_time = datetime.min
        
        # 性能统计
        self.stats = {
            'total_predictions': 0,
            'attack_predictions': 0,
            'model_performance': {},
            'feature_importance': {},
            'prediction_times': deque(maxlen=100)
        }
    
    def _initialize_models(self) -> None:
        """初始化机器学习模型"""
        if self.model_config.get('random_forest', True):
            self.models['random_forest'] = RandomForestModel()
        
        if self.model_config.get('anomaly_detection', True):
            self.models['anomaly_detection'] = AnomalyDetectionModel()
        
        if self.model_config.get('deep_learning', False) and TENSORFLOW_AVAILABLE:
            try:
                self.models['deep_learning'] = DeepLearningModel()
            except ImportError:
                self.logger.warning("深度学习模型初始化失败，跳过")
        
        # 加载预训练模型
        self._load_pretrained_models()
    
    def _load_pretrained_models(self) -> None:
        """加载预训练模型"""
        models_dir = Path(self.config.get('models_dir', 'models'))
        
        for model_name, model in self.models.items():
            model_path = models_dir / f'{model_name}.joblib'
            if model_path.exists():
                try:
                    model.load_model(str(model_path))
                    self.logger.info(f"已加载预训练模型: {model_name}")
                except Exception as e:
                    self.logger.error(f"加载模型 {model_name} 失败: {e}")
    
    async def detect_attack(self, request_data: Dict[str, Any], 
                           ip_history: Optional[List[Dict[str, Any]]] = None) -> MLPrediction:
        """检测攻击
        
        Args:
            request_data: 请求数据
            ip_history: IP历史记录
            
        Returns:
            预测结果
        """
        start_time = time.time()
        
        try:
            # 提取特征
            features = self.feature_extractor.extract_all_features(request_data, ip_history)
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            
            # 使用集成模型预测（如果可用）
            if self.ensemble_model and self.ensemble_model.is_trained:
                prediction = self.ensemble_model.predict(feature_vector)
            else:
                # 使用单个最佳模型
                best_model = self._get_best_model()
                if best_model and best_model.is_trained:
                    prediction = best_model.predict(feature_vector)
                else:
                    # 返回默认预测
                    prediction = MLPrediction(
                        is_attack=False,
                        attack_type=None,
                        confidence=0.5,
                        probability_scores={'normal': 0.5, 'attack': 0.5},
                        feature_importance={},
                        model_name='default',
                        prediction_time=datetime.now()
                    )
            
            # 记录预测时间
            prediction_time = time.time() - start_time
            self.stats['prediction_times'].append(prediction_time)
            
            # 更新统计
            self.stats['total_predictions'] += 1
            if prediction.is_attack:
                self.stats['attack_predictions'] += 1
            
            # 缓存预测结果
            self.prediction_cache.append({
                'request_data': request_data,
                'features': features,
                'prediction': prediction,
                'timestamp': datetime.now()
            })
            
            return prediction
            
        except Exception as e:
            self.logger.error(f"攻击检测时发生错误: {e}")
            return MLPrediction(
                is_attack=False,
                attack_type=None,
                confidence=0.0,
                probability_scores={},
                feature_importance={},
                model_name='error',
                prediction_time=datetime.now()
            )
    
    def _get_best_model(self) -> Optional[MLModel]:
        """获取最佳模型"""
        best_model = None
        best_score = 0
        
        for model in self.models.values():
            if model.is_trained and model.training_history:
                # 获取最新的训练结果
                latest_result = model.training_history[-1]
                score = latest_result.get('validation_accuracy', 
                                        latest_result.get('final_val_accuracy', 0))
                
                if score > best_score:
                    best_score = score
                    best_model = model
        
        return best_model
    
    async def add_training_data(self, request_data: Dict[str, Any], 
                               label: str, ip_history: Optional[List[Dict[str, Any]]] = None) -> None:
        """添加训练数据
        
        Args:
            request_data: 请求数据
            label: 标签（normal, sql_injection, xss等）
            ip_history: IP历史记录
        """
        features = self.feature_extractor.extract_all_features(request_data, ip_history)
        
        training_sample = {
            'features': features,
            'label': label,
            'timestamp': datetime.now(),
            'request_data': request_data
        }
        
        self.training_data.append(training_sample)
        
        # 检查是否需要重新训练
        if self.auto_retrain:
            await self._check_retrain_condition()
    
    async def _check_retrain_condition(self) -> None:
        """检查重新训练条件"""
        now = datetime.now()
        time_since_last_training = (now - self.last_training_time).total_seconds()
        
        # 检查数据量阈值或时间间隔
        if (len(self.training_data) >= self.retrain_threshold or 
            time_since_last_training >= self.retrain_interval):
            
            await self.retrain_models()
    
    async def retrain_models(self) -> Dict[str, Any]:
        """重新训练模型"""
        if len(self.training_data) < 100:  # 最少需要100个样本
            self.logger.warning("训练数据不足，跳过重新训练")
            return {}
        
        self.logger.info("开始重新训练模型...")
        
        # 准备训练数据
        features_list = []
        labels_list = []
        
        for sample in self.training_data:
            features_list.append(list(sample['features'].values()))
            labels_list.append(sample['label'])
        
        X = np.array(features_list)
        y = np.array(labels_list)
        
        # 更新特征名称
        if self.training_data:
            self.feature_extractor.feature_names = list(self.training_data[0]['features'].keys())
            for model in self.models.values():
                model.feature_names = self.feature_extractor.feature_names
        
        # 训练各个模型
        training_results = {}
        trained_models = []
        
        for model_name, model in self.models.items():
            try:
                self.logger.info(f"训练模型: {model_name}")
                result = model.train(X, y)
                training_results[model_name] = result
                trained_models.append(model)
                
                # 保存模型
                await self._save_model(model, model_name)
                
            except Exception as e:
                self.logger.error(f"训练模型 {model_name} 时发生错误: {e}")
        
        # 创建集成模型
        if len(trained_models) > 1:
            self.ensemble_model = EnsembleModel(trained_models)
            ensemble_result = self.ensemble_model.train(X, y)
            training_results['ensemble'] = ensemble_result
        
        self.last_training_time = datetime.now()
        
        # 更新性能统计
        self.stats['model_performance'] = training_results
        
        self.logger.info("模型重新训练完成")
        return training_results
    
    async def _save_model(self, model: MLModel, model_name: str) -> None:
        """保存模型"""
        try:
            models_dir = Path(self.config.get('models_dir', 'models'))
            models_dir.mkdir(parents=True, exist_ok=True)
            
            model_path = models_dir / f'{model_name}.joblib'
            model.save_model(str(model_path))
            
        except Exception as e:
            self.logger.error(f"保存模型 {model_name} 时发生错误: {e}")
    
    def get_model_statistics(self) -> Dict[str, Any]:
        """获取模型统计信息"""
        model_stats = {}
        
        for model_name, model in self.models.items():
            model_stats[model_name] = {
                'is_trained': model.is_trained,
                'training_history': model.training_history,
                'model_type': model.model_type
            }
        
        # 预测时间统计
        prediction_times = list(self.stats['prediction_times'])
        prediction_time_stats = {}
        if prediction_times:
            prediction_time_stats = {
                'avg_prediction_time': np.mean(prediction_times),
                'max_prediction_time': np.max(prediction_times),
                'min_prediction_time': np.min(prediction_times)
            }
        
        return {
            'models': model_stats,
            'ensemble_trained': self.ensemble_model is not None and self.ensemble_model.is_trained,
            'training_data_size': len(self.training_data),
            'total_predictions': self.stats['total_predictions'],
            'attack_predictions': self.stats['attack_predictions'],
            'attack_detection_rate': self.stats['attack_predictions'] / max(self.stats['total_predictions'], 1),
            'prediction_time_stats': prediction_time_stats,
            'last_training_time': self.last_training_time.isoformat(),
            'auto_retrain_enabled': self.auto_retrain
        }
    
    async def export_training_data(self, filepath: str) -> None:
        """导出训练数据
        
        Args:
            filepath: 导出文件路径
        """
        training_data_list = []
        
        for sample in self.training_data:
            training_data_list.append({
                'features': sample['features'],
                'label': sample['label'],
                'timestamp': sample['timestamp'].isoformat(),
                'request_data': sample['request_data']
            })
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(training_data_list, f, ensure_ascii=False, indent=2)
        
        self.logger.info(f"训练数据已导出到: {filepath}")
    
    async def import_training_data(self, filepath: str) -> None:
        """导入训练数据
        
        Args:
            filepath: 导入文件路径
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                training_data_list = json.load(f)
            
            for sample_data in training_data_list:
                sample = {
                    'features': sample_data['features'],
                    'label': sample_data['label'],
                    'timestamp': datetime.fromisoformat(sample_data['timestamp']),
                    'request_data': sample_data['request_data']
                }
                self.training_data.append(sample)
            
            self.logger.info(f"已导入 {len(training_data_list)} 个训练样本")
            
        except Exception as e:
            self.logger.error(f"导入训练数据时发生错误: {e}")