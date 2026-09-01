"""T3-3 Source Code & ABI Fetcher."""

import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Optional
import requests
from web3 import Web3
from .config import CHAINS
from .db import Database


class SourceFetcher:
    def __init__(self, db: Database = None):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VulnHunter/2.0"})
        self._cache = {}

    def fetch_source(self, address: str, chain_id: int):
        cache_key = f"{chain_id}:{address.lower()}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        chain = CHAINS.get(chain_id)
        if not chain:
            return None
        api_key = chain.get('api_key', '')
        params = {
            'chainid': chain_id,
            'module': 'contract', 'action': 'getsourcecode',
            'address': address, 'apikey': api_key,
        }
        try:
            r = self.session.get(chain['explorer_api'], params=params, timeout=30)
            r.raise_for_status()
            data = r.json()
            if data.get('status') != '1' or not data.get('result'):
                self._cache[cache_key] = None
                return None
            result = data['result'][0] if isinstance(data['result'], list) else data['result']
            source = result.get('SourceCode', '')
            if not source or len(source) < 50:
                self._cache[cache_key] = None
                return None
            parsed = {
                'source_code': source, 'abi': result.get('ABI', '[]'),
                'contract_name': result.get('ContractName', ''),
                'compiler_version': result.get('CompilerVersion', ''),
                'optimization_used': result.get('OptimizationUsed') == '1',
                'runs': int(result.get('Runs', '200') or '200'),
                'proxy': result.get('Proxy', '0'),
                'implementation': result.get('Implementation', ''),
            }
            parsed['multi_file'] = self._parse_multi_file_source(source)
            parsed['abi_parsed'] = self._parse_abi(parsed['abi'])
            self._cache[cache_key] = parsed
            return parsed
        except Exception:
            self._cache[cache_key] = None
            return None

    def prepare_source_for_slither(self, source_data, address):
        if not source_data or not source_data.get('source_code'):
            return None
        source = source_data['source_code']
        contract_name = source_data.get('contract_name', 'Contract')
        tmp_dir = tempfile.mkdtemp(prefix='vulnhunt_')
        multi = source_data.get('multi_file')
        if multi and isinstance(multi, dict):
            for file_path, file_content in multi.items():
                full_path = os.path.join(tmp_dir, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, 'w') as f:
                    f.write(file_content)
        else:
            sol_path = os.path.join(tmp_dir, f'{contract_name}.sol')
            with open(sol_path, 'w') as f:
                f.write(source)
        return tmp_dir

    def get_bytecode(self, address, chain_id):
        chain = CHAINS.get(chain_id)
        if not chain:
            return None
        try:
            w3 = Web3(Web3.HTTPProvider(chain['rpc'], request_kwargs={'timeout': 15}))
            if not w3.is_connected():
                return None
            code = w3.eth.get_code(Web3.to_checksum_address(address))
            if code and len(code) > 2:
                return code.hex()
        except Exception:
            pass
        return None

    def _parse_multi_file_source(self, source):
        if source.startswith('{{'):
            source = source[1:-1] if source.endswith('}}') else source[1:]
        try:
            parsed = json.loads(source)
            if isinstance(parsed, dict) and 'sources' in parsed:
                return {k: v.get('content', '') for k, v in parsed['sources'].items()}
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if isinstance(v, str) and len(v) > 200:
                        return parsed
        except (json.JSONDecodeError, TypeError):
            pass
        return None

    def _parse_abi(self, abi_str):
        try:
            abi = json.loads(abi_str) if isinstance(abi_str, str) else abi_str
            if not isinstance(abi, list):
                return []
            return abi
        except (json.JSONDecodeError, TypeError):
            return []

    def get_dangerous_functions(self, abi_parsed):
        dangerous_names = {
            'withdraw', 'withdrawAll', 'sweep', 'emergencyWithdraw',
            'mint', 'burn', 'setOwner', 'transferOwnership',
            'setFee', 'setFeeRate', 'setSwapFee', 'setProtocolFee',
            'setOracle', 'setPriceFeed', 'setPauser', 'pause', 'unpause',
            'setImplementation', 'upgradeTo', 'upgradeToAndCall',
            'addPool', 'removePool', 'setPool', 'setPoolParams',
            'grantRole', 'revokeRole', 'setRoleAdmin',
            'initialize', 'reinitialize', 'init',
            'selfdestruct', 'destroy', 'claim', 'claimRewards',
        }
        dangerous = []
        for item in abi_parsed:
            if item.get('type') != 'function':
                continue
            name = item.get('name', '')
            if name.lower() in {d.lower() for d in dangerous_names}:
                dangerous.append({
                    'name': name, 'inputs': item.get('inputs', []),
                    'payable': item.get('stateMutability') == 'payable',
                    'stateMutability': item.get('stateMutability', ''),
                })
        return dangerous

    def get_external_functions(self, abi_parsed):
        functions = []
        for item in abi_parsed:
            if item.get('type') != 'function':
                continue
            mutability = item.get('stateMutability', '')
            if mutability in ('nonpayable', 'payable'):
                functions.append({
                    'name': item.get('name', ''),
                    'inputs': item.get('inputs', []),
                    'payable': mutability == 'payable',
                    'outputs': item.get('outputs', []),
                    'selector': self._get_selector(item),
                })
        return functions

    def _get_selector(self, abi_item):
        name = abi_item.get('name', '')
        inputs = ','.join(i.get('type', '') for i in abi_item.get('inputs', []))
        sig = f"{name}({inputs})"
        return Web3.keccak(text=sig)[:4].hex()
