#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
多链钱包批量验证器 - 防封IP终极版
支持：BTC、ETH、USDT
策略：代理池轮换、动态限流、User-Agent轮换、多API备用、失败重试
"""

from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import requests
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from datetime import datetime, timedelta
import os
import json
import urllib3
import signal
import sys
from collections import deque
import hashlib

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== 代理池 ====================
class SmartProxyPool:
    """智能代理池 - 自动获取、轮换、检测可用性"""
    
    def __init__(self):
        self.proxies = []
        self.failed_proxies = set()
        self.success_proxies = set()
        self.lock = threading.Lock()
        self.current_index = 0
        self.last_refresh = 0
        self._load_proxies()
    
    def _load_proxies(self):
        """加载代理列表（多源获取）"""
        print("🌐 正在加载代理池...")
        all_proxies = []
        
        # 代理源列表
        proxy_sources = [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=5000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        ]
        
        for url in proxy_sources:
            try:
                print(f"  📡 从 {url.split('/')[2]} 获取代理...")
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    proxy_list = resp.text.strip().split('\n')
                    for proxy in proxy_list:
                        proxy = proxy.strip()
                        if proxy and ':' in proxy:
                            if not proxy.startswith('http'):
                                proxy = f"http://{proxy}"
                            all_proxies.append(proxy)
                    print(f"  ✅ 获取到 {len(proxy_list)} 个代理")
                    break
            except:
                continue
        
        # 备用硬编码代理
        if len(all_proxies) < 20:
            print("  ⚠️ 使用备用代理池")
            backup_proxies = [
                "http://103.152.112.120:80",
                "http://103.142.78.206:80",
                "http://103.134.23.58:8080",
                "http://103.176.108.114:80",
                "http://103.177.242.242:80",
                "http://103.181.200.190:8080",
                "http://103.186.180.166:80",
                "http://103.47.188.42:8080",
                "http://103.49.202.248:80",
                "http://103.82.172.29:80",
                "http://103.149.31.146:8080",
                "http://103.154.170.242:80",
                "http://103.168.158.250:8080",
                "http://103.173.24.184:80",
                "http://103.174.252.137:8080",
                "http://103.176.179.18:8080",
                "http://103.179.143.116:8080",
                "http://103.183.234.34:80",
                "http://103.186.180.166:80",
                "http://103.216.82.232:8080",
                "http://103.216.82.236:8080",
                "http://103.216.82.250:8080",
                "http://103.216.82.19:8080",
                "http://103.216.82.20:8080",
                "http://103.216.82.21:8080",
            ]
            all_proxies.extend(backup_proxies)
        
        # 去重
        self.proxies = list(set(all_proxies))
        random.shuffle(self.proxies)
        
        print(f"✅ 代理池加载完成: {len(self.proxies)} 个代理")
    
    def get_proxy(self):
        """获取下一个可用代理（轮询 + 跳过失败）"""
        with self.lock:
            if not self.proxies:
                return None
            
            max_attempts = len(self.proxies)
            attempts = 0
            
            while attempts < max_attempts:
                proxy = self.proxies[self.current_index % len(self.proxies)]
                self.current_index += 1
                attempts += 1
                
                if proxy in self.failed_proxies:
                    continue
                
                return {"http": proxy, "https": proxy}
            
            # 所有代理都失败，重置
            print("🔄 所有代理标记为失败，重置代理池...")
            self.failed_proxies.clear()
            return self.get_proxy()
    
    def mark_success(self, proxy):
        """标记代理成功"""
        if proxy:
            with self.lock:
                proxy_url = proxy.get('http', '')
                if proxy_url in self.failed_proxies:
                    self.failed_proxies.remove(proxy_url)
                self.success_proxies.add(proxy_url)
    
    def mark_failed(self, proxy):
        """标记代理失败"""
        if proxy:
            with self.lock:
                proxy_url = proxy.get('http', '')
                self.failed_proxies.add(proxy_url)
                if proxy_url in self.success_proxies:
                    self.success_proxies.remove(proxy_url)
    
    def get_stats(self):
        """获取代理池统计"""
        return {
            "total": len(self.proxies),
            "failed": len(self.failed_proxies),
            "success": len(self.success_proxies),
            "available": len(self.proxies) - len(self.failed_proxies)
        }

# ==================== 主验证器 ====================
class AntiBanWalletVerifier:
    """防封IP验证器 - 集成所有防护策略"""
    
    def __init__(self, max_workers=5, rate_limit=0.5, runtime_minutes=360):
        """
        max_workers: 并发数（防封建议3-5）
        rate_limit: 基础请求间隔（秒）
        runtime_minutes: 最大运行时间（分钟）
        """
        self.max_workers = max_workers
        self.base_rate_limit = rate_limit
        self.runtime_minutes = runtime_minutes
        self.start_time = datetime.now()
        self.end_time = self.start_time + timedelta(minutes=runtime_minutes)
        
        self.lock = threading.Lock()
        self.last_request_time = 0
        self.request_counter = 0
        self.rate_limit_triggered = False
        
        # 代理池
        self.proxy_pool = SmartProxyPool()
        
        # User-Agent池（10种不同浏览器）
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        ]
        
        # 备用API（多个，防止单个API被封）
        self.api_configs = {
            "BTC": [
                "https://blockchain.info/q/addressbalance/{}",
                "https://blockchain.info/balance?active={}",
                "https://api.blockchair.com/bitcoin/dashboards/address/{}",
            ],
            "ETH": [
                "https://api.etherscan.io/api?module=account&action=balance&address={}&tag=latest",
                "https://api.ethplorer.io/getAddressInfo/{}?apiKey=freekey",
            ],
            "USDT": [
                "https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress=0xdAC17F958D2ee523a2206206994597C13D831ec7&address={}&tag=latest",
            ]
        }
        
        # API使用统计
        self.api_usage = {chain: 0 for chain in self.api_configs}
        self.api_failures = {chain: 0 for chain in self.api_configs}
        
        # 统计
        self.stats = {
            "total_requests": 0,
            "success_requests": 0,
            "fail_requests": 0,
            "rate_limits": 0,
            "proxy_switches": 0,
        }
        
        self.found_wallets = []
        self.processed_count = 0
        self.is_running = True
        self.found_count = 0
        
        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """处理中断信号"""
        print("\n🛑 收到停止信号，正在保存进度...")
        self.is_running = False
    
    def _is_time_expired(self):
        """检查是否超时"""
        if datetime.now() >= self.end_time:
            return True
        return False
    
    def _get_remaining_time(self):
        """获取剩余时间（秒）"""
        remaining = (self.end_time - datetime.now()).total_seconds()
        return max(0, remaining)
    
    def _save_progress(self):
        """保存进度"""
        progress_file = f"PROGRESS_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(progress_file, 'w', encoding='utf-8') as f:
            f.write(f"# 验证进度\n")
            f.write(f"处理数量: {self.processed_count}\n")
            f.write(f"找到钱包: {len(self.found_wallets)}\n")
            f.write(f"运行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"剩余时间: {self._get_remaining_time()/60:.1f} 分钟\n")
            
            if self.found_wallets:
                f.write(f"\n# 找到的钱包\n")
                for w in self.found_wallets:
                    f.write(f"{w['mnemonic']}\n")
    
    def _get_dynamic_delay(self):
        """动态延迟（根据请求成功率调整）"""
        base_delay = self.base_rate_limit
        
        # 如果失败率过高，增加延迟
        if self.stats["total_requests"] > 10:
            fail_rate = self.stats["fail_requests"] / self.stats["total_requests"]
            if fail_rate > 0.3:
                base_delay *= 2
            elif fail_rate > 0.5:
                base_delay *= 3
        
        # 如果触发限流，增加延迟
        if self.rate_limit_triggered:
            base_delay *= 2
        
        # 随机抖动（防检测）
        jitter = random.uniform(0.8, 1.2)
        return base_delay * jitter
    
    def _random_delay(self):
        """随机延迟（防模式识别）"""
        delay = self._get_dynamic_delay()
        time.sleep(delay)
    
    def _get_random_headers(self):
        """随机请求头"""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
        }
    
    def _rate_limited_request(self, url, max_retries=3):
        """智能限流请求 - 核心防封方法"""
        # 限流
        with self.lock:
            current_time = time.time()
            min_interval = self.base_rate_limit
            
            if self.rate_limit_triggered:
                min_interval *= 3  # 被限流后增加间隔
            
            elapsed = current_time - self.last_request_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            
            self.last_request_time = time.time()
            self.request_counter += 1
        
        # 随机延迟（增加抖动）
        self._random_delay()
        
        # 重试机制
        for attempt in range(max_retries):
            try:
                # 获取代理
                proxy = self.proxy_pool.get_proxy()
                if proxy:
                    self.stats["proxy_switches"] += 1
                
                # 请求头
                headers = self._get_random_headers()
                
                # 发送请求
                response = requests.get(
                    url,
                    proxies=proxy,
                    headers=headers,
                    timeout=10,
                    verify=False
                )
                
                self.stats["total_requests"] += 1
                
                # 处理响应状态码
                if response.status_code == 200:
                    self.stats["success_requests"] += 1
                    if proxy:
                        self.proxy_pool.mark_success(proxy)
                    return response
                
                elif response.status_code == 429:  # Too Many Requests
                    self.stats["rate_limits"] += 1
                    self.rate_limit_triggered = True
                    wait_time = 2 ** attempt * 10
                    print(f"⚠️ 触发限流 (429)，等待 {wait_time} 秒...")
                    time.sleep(wait_time)
                    if proxy:
                        self.proxy_pool.mark_failed(proxy)
                    continue
                
                elif response.status_code == 403:  # Forbidden
                    print(f"⚠️ IP被禁止 (403)，切换代理...")
                    if proxy:
                        self.proxy_pool.mark_failed(proxy)
                    continue
                
                elif response.status_code == 404:  # Not Found
                    self.stats["fail_requests"] += 1
                    return None
                
                else:
                    self.stats["fail_requests"] += 1
                    if proxy:
                        self.proxy_pool.mark_failed(proxy)
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    return None
                    
            except requests.exceptions.Timeout:
                self.stats["fail_requests"] += 1
                if proxy:
                    self.proxy_pool.mark_failed(proxy)
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                    
            except requests.exceptions.ConnectionError:
                self.stats["fail_requests"] += 1
                if proxy:
                    self.proxy_pool.mark_failed(proxy)
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
            
            except Exception as e:
                self.stats["fail_requests"] += 1
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
        
        return None
    
    def derive_addresses(self, mnemonic):
        """派生BTC和ETH地址"""
        try:
            if not Mnemonic('english').check(mnemonic):
                return None, None
            
            seed = Bip39SeedGenerator(mnemonic).Generate()
            
            # BTC地址
            bip44_btc = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            btc_addr = bip44_btc.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
            
            # ETH地址
            bip44_eth = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
            eth_addr = bip44_eth.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
            
            return btc_addr, eth_addr
        except:
            return None, None
    
    def check_balance(self, btc_addr, eth_addr):
        """查询三种资产余额（使用多个备用API）"""
        result = {"BTC": 0.0, "ETH": 0.0, "USDT": 0.0, "has_balance": False}
        
        # 查询BTC - 尝试多个API
        for api_url in self.api_configs["BTC"]:
            url = api_url.format(btc_addr)
            resp = self._rate_limited_request(url)
            if resp:
                try:
                    if "blockchair" in api_url:
                        data = resp.json()
                        if data.get("data", {}).get(btc_addr, {}).get("address", {}).get("balance"):
                            result["BTC"] = data["data"][btc_addr]["address"]["balance"] / 1e8
                    elif "balance?active" in api_url:
                        data = resp.json()
                        if btc_addr in data:
                            result["BTC"] = data[btc_addr]["final_balance"] / 1e8
                    else:
                        result["BTC"] = int(resp.text) / 1e8
                    break
                except:
                    continue
        
        # 查询ETH - 尝试多个API
        for api_url in self.api_configs["ETH"]:
            url = api_url.format(eth_addr)
            resp = self._rate_limited_request(url)
            if resp:
                try:
                    data = resp.json()
                    if "etherscan" in api_url and data.get("status") == "1":
                        result["ETH"] = int(data["result"]) / 1e18
                        break
                    elif "ethplorer" in api_url and data.get("ETH"):
                        result["ETH"] = data["ETH"]["balance"] / 1e18
                        break
                except:
                    continue
        
        # 查询USDT
        for api_url in self.api_configs["USDT"]:
            url = api_url.format(eth_addr)
            resp = self._rate_limited_request(url)
            if resp:
                try:
                    data = resp.json()
                    if data.get("status") == "1":
                        result["USDT"] = int(data["result"]) / 1e6
                        break
                except:
                    continue
        
        # 判断是否有余额（阈值可调）
        if result["BTC"] > 0.000001 or result["ETH"] > 0.0001 or result["USDT"] > 0.01:
            result["has_balance"] = True
        
        return result
    
    def verify_single(self, mnemonic, idx):
        """验证单个助记词"""
        try:
            # 检查是否超时
            if self._is_time_expired():
                return "TIME_EXPIRED"
            
            btc_addr, eth_addr = self.derive_addresses(mnemonic)
            if not btc_addr or not eth_addr:
                return None
            
            balances = self.check_balance(btc_addr, eth_addr)
            
            if balances["has_balance"]:
                return {
                    "index": idx,
                    "mnemonic": mnemonic,
                    "btc_addr": btc_addr,
                    "eth_addr": eth_addr,
                    "balances": balances,
                    "total_usd": balances["BTC"]*60000 + balances["ETH"]*3000 + balances["USDT"]
                }
            return None
        except:
            return None
    
    def run(self, candidates):
        """主运行循环"""
        print(f"\n⏳ 开始验证，将持续运行 {self.runtime_minutes} 分钟")
        print(f"⏰ 预计结束时间: {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📊 总共 {len(candidates)} 个候选\n")
        
        batch_size = 10  # 每批处理10个
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for i in range(0, len(candidates), batch_size):
                # 检查是否超时
                if self._is_time_expired() or not self.is_running:
                    print(f"\n⏰ 运行时间到，停止验证...")
                    break
                
                batch = candidates[i:i+batch_size]
                futures = {executor.submit(self.verify_single, m, i+j): (i+j, m) 
                          for j, m in enumerate(batch)}
                
                for future in as_completed(futures):
                    if self._is_time_expired() or not self.is_running:
                        print(f"\n⏰ 运行时间到，停止验证...")
                        break
                    
                    result = future.result()
                    self.processed_count += 1
                    
                    if result and result != "TIME_EXPIRED":
                        self.found_wallets.append(result)
                        self.found_count += 1
                        print(f"\n✅ 找到钱包 #{self.found_count}")
                        print(f"  助记词: {result['mnemonic'][:30]}...")
                        print(f"  总价值: ${result['total_usd']:.2f}")
                    
                    # 每处理一些显示进度
                    if self.processed_count % 10 == 0:
                        remaining = self._get_remaining_time()
                        print(f"\n📊 已处理: {self.processed_count}/{len(candidates)} | "
                              f"找到: {self.found_count} | "
                              f"剩余时间: {remaining/60:.1f} 分钟")
                        self._save_progress()
        
        # 最终保存
        self._save_progress()
        return self.processed_count
    
    def get_stats(self):
        """获取完整统计"""
        proxy_stats = self.proxy_pool.get_stats()
        return {
            **self.stats,
            "proxy_stats": proxy_stats,
            "found_count": self.found_count,
            "processed_count": self.processed_count,
            "success_rate": f"{self.stats['success_requests']/(self.stats['total_requests'] or 1)*100:.1f}%"
        }

# ==================== 主程序 ====================
def main():
    print("="*70)
    print("🛡️ 防封IP钱包验证器 v5.0")
    print("   支持: BTC + ETH + USDT")
    print("   策略: 代理池 + 动态限流 + UA轮换 + 多API备用")
    print("="*70)
    
    # 从环境变量读取配置（GitHub Actions用）
    max_workers = int(os.environ.get('MAX_WORKERS', '5'))
    rate_limit = float(os.environ.get('RATE_LIMIT', '0.5'))
    runtime_minutes = int(os.environ.get('RUNTIME_MINUTES', '360'))
    
    # 读取candidates.txt
    try:
        with open('candidates.txt', 'r', encoding='utf-8') as f:
            candidates = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("❌ 找不到 candidates.txt 文件！")
        print("💡 请在仓库根目录创建 candidates.txt")
        return
    
    if not candidates:
        print("❌ candidates.txt 为空")
        return
    
    print(f"\n📂 读取到 {len(candidates)} 个候选助记词")
    print(f"⚡ 并发线程: {max_workers}（防封推荐5）")
    print(f"⏱️  请求间隔: {rate_limit}秒（动态调整）")
    print(f"🕐 运行时间: {runtime_minutes} 分钟")
    print(f"🛡️  代理池: 自动获取+智能切换")
    print(f"🔄 API备用: 每个链3个备用API")
    print("="*70)
    
    # 初始化验证器
    verifier = AntiBanWalletVerifier(
        max_workers=max_workers,
        rate_limit=rate_limit,
        runtime_minutes=runtime_minutes
    )
    
    # 运行
    processed = verifier.run(candidates)
    
    # 统计
    stats = verifier.get_stats()
    
    print(f"\n{'='*70}")
    print("📊 验证完成统计")
    print(f"{'='*70}")
    print(f"✅ 扫描候选: {processed}")
    print(f"💰 找到钱包: {stats['found_count']}")
    print(f"⏱️  运行时间: {runtime_minutes} 分钟")
    print(f"📡 总请求: {stats['total_requests']}")
    print(f"✅ 成功: {stats['success_requests']}")
    print(f"❌ 失败: {stats['fail_requests']}")
    print(f"📈 成功率: {stats['success_rate']}")
    print(f"🚫 触发限流: {stats['rate_limits']} 次")
    print(f"🌐 代理切换: {stats['proxy_switches']} 次")
    print(f"🟢 活跃代理: {stats['proxy_stats']['available']}/{stats['proxy_stats']['total']}")
    
    if verifier.found_wallets:
        # 按总资产排序
        verifier.found_wallets.sort(key=lambda x: x['total_usd'], reverse=True)
        
        # 保存结果
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        result_file = f"FOUND_WALLETS_{timestamp}.txt"
        
        with open(result_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write(f"✅ 找到 {len(verifier.found_wallets)} 个有资产的钱包\n")
            f.write(f"验证时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            for i, w in enumerate(verifier.found_wallets, 1):
                f.write(f"【钱包 #{i}】\n")
                f.write(f"助记词: {w['mnemonic']}\n")
                f.write(f"BTC地址: {w['btc_addr']}\n")
                f.write(f"ETH地址: {w['eth_addr']}\n")
                f.write(f"BTC余额: {w['balances']['BTC']:.8f}\n")
                f.write(f"ETH余额: {w['balances']['ETH']:.6f}\n")
                f.write(f"USDT余额: {w['balances']['USDT']:.2f}\n")
                f.write(f"总价值(USD): ${w['total_usd']:.2f}\n")
                f.write("-"*80 + "\n\n")
        
        print(f"\n💾 结果已保存到: {result_file}")
        
        # 简化版
        simple_file = f"MNEMONICS_FOUND_{timestamp}.txt"
        with open(simple_file, 'w', encoding='utf-8') as f:
            for w in verifier.found_wallets:
                f.write(f"{w['mnemonic']}\n")
        
        print(f"💾 助记词列表: {simple_file}")
        
        # 显示资产排名
        print("\n💰 资产排名:")
        for i, w in enumerate(verifier.found_wallets[:10], 1):
            print(f"  #{i}: ${w['total_usd']:.2f} | {w['mnemonic'][:30]}...")
    else:
        print("\n❌ 未找到任何有余额的钱包")
        print("💡 建议:")
        print("  1. 检查 candidates.txt 里的助记词是否正确")
        print("  2. 降低余额阈值（修改代码里的阈值）")
        print("  3. 检查网络连接")
    
    print(f"\n{'='*70}")

if __name__ == "__main__":
    main()