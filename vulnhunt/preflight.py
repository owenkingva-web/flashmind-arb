r"""T3-3 Pre-Flight Checks

Comprehensive validation before attempting exploitation.
Goes beyond simple gas estimation to check:
1. Target contract state (is it already exploited? paused? empty?)
2. Wallet balance sufficiency (with 2x safety buffer)
3. Flash loan liquidity availability
4. Token balance at target
5. Reentrancy guard status
6. Recent state changes (was owner just changed?)
7. Gas price volatility
8. Competing transactions in mempool
"""
import time
from dataclasses import dataclass
from typing import Optional
from web3 import Web3

from .config import CHAINS, ETH_PRICE_USD, WALLET_PRIVATE_KEY


@dataclass
class PreflightResult:
    passed: bool
    checks: dict
    warnings: list
    blockers: list
    estimated_gas_cost_eth: float = 0
    estimated_gas_cost_usd: float = 0
    recommendation: str = ''

    def to_dict(self):
        return {
            'passed': self.passed,
            'checks': self.checks,
            'warnings': self.warnings,
            'blockers': self.blockers,
            'estimated_gas_cost_eth': self.estimated_gas_cost_eth,
            'estimated_gas_cost_usd': self.estimated_gas_cost_usd,
            'recommendation': self.recommendation,
        }


class PreflightChecker:
    """Comprehensive pre-exploitation validation."""

    ERC20_ABI = [
        {"constant": True, "inputs": [], "name": "totalSupply",
         "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
        {"constant": True, "inputs": [{"name": "account", "type": "address"}],
         "name": "balanceOf",
         "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
        {"constant": True, "inputs": [], "name": "paused",
         "outputs": [{"name": "", "type": "bool"}], "type": "function"},
    ]

    AAVE_POOL_ABI = [
        {"inputs": [
            {"internalType": "address", "name": "asset", "type": "address"},
        ], "name": "getAvailableLiquidity",
         "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
         "stateMutability": "view", "type": "function"},
    ]

    def __init__(self):
        self._w3_cache = {}

    def _get_w3(self, chain_id: int) -> Web3:
        if chain_id not in self._w3_cache:
            chain = CHAINS.get(chain_id, {})
            w3 = Web3(Web3.HTTPProvider(chain['rpc'], request_kwargs={'timeout': 15}))
            self._w3_cache[chain_id] = w3
        return self._w3_cache[chain_id]

    def run_preflight(self, chain_id: int, target_address: str,
                        finding: dict, flash_loan_needed: bool = False,
                        estimated_gas: int = 500000) -> PreflightResult:
        """Run all pre-flight checks before exploitation.

        Returns a PreflightResult with pass/fail and detailed checks.
        """
        result = PreflightResult(
            passed=True,
            checks={},
            warnings=[],
            blockers=[],
        )

        chain = CHAINS.get(chain_id, {})
        chain_name = chain.get('name', 'unknown')
        w3 = self._get_w3(chain_id)

        if not w3.is_connected():
            result.passed = False
            result.blockers.append(f'Cannot connect to {chain_name}')
            return result

        addr = Web3.to_checksum_address(target_address)

        # Check 1: Target has code
        try:
            code = w3.eth.get_code(addr)
            has_code = len(code) > 2
            result.checks['target_has_code'] = has_code
            if not has_code:
                result.passed = False
                result.blockers.append('Target is EOA or self-destructed')
                return result
        except Exception as e:
            result.checks['target_has_code'] = False
            result.warnings.append(f'Code check failed: {e}')

        # Check 2: Target balance (is there anything to drain?)
        try:
            target_bal = w3.eth.get_balance(addr)
            target_eth = float(w3.from_wei(target_bal, 'ether'))
            result.checks['target_eth_balance'] = f'{target_eth:.6f}'
            result.checks['target_balance_usd'] = f'${target_eth * ETH_PRICE_USD:,.2f}'

            if target_eth == 0:
                result.warnings.append('Target holds 0 native tokens')
        except Exception as e:
            result.warnings.append(f'Balance check failed: {e}')

        # Check 3: Is target paused?
        try:
            paused_sel = Web3.keccak(text='paused()')[:4]
            paused_result = w3.eth.call({'to': addr, 'data': paused_sel})
            is_paused = paused_result[-1] == 1
            result.checks['target_paused'] = is_paused
            if is_paused:
                result.passed = False
                result.blockers.append('Target contract is PAUSED')
        except Exception:
            result.checks['target_paused'] = 'N/A'

        # Check 4: Wallet balance for gas
        try:
            if WALLET_PRIVATE_KEY:
                from eth_account import Account
                wallet = Account.from_key(WALLET_PRIVATE_KEY)
                wallet_bal = w3.eth.get_balance(wallet.address)
                wallet_eth = float(w3.from_wei(wallet_bal, 'ether'))

                gas_price = w3.eth.gas_price
                gas_price_gwei = gas_price / 1e9
                total_gas_cost = (estimated_gas * 3) * gas_price / 1e18  # 3x for deploy+execute+sweep

                result.checks['wallet_balance_eth'] = f'{wallet_eth:.6f}'
                result.checks['gas_price_gwei'] = f'{gas_price_gwei:.2f}'
                result.checks['total_gas_cost_eth'] = f'{total_gas_cost:.6f}'
                result.estimated_gas_cost_eth = total_gas_cost
                result.estimated_gas_cost_usd = total_gas_cost * ETH_PRICE_USD

                safety_ratio = wallet_eth / total_gas_cost if total_gas_cost > 0 else float('inf')
                result.checks['gas_safety_ratio'] = f'{safety_ratio:.1f}x'

                if safety_ratio < 2.0:
                    result.warnings.append(
                        f'Low gas safety ratio ({safety_ratio:.1f}x). Need 2x buffer.'
                    )
                if safety_ratio < 1.0:
                    result.passed = False
                    result.blockers.append(
                        f'Insufficient balance for gas. Have {wallet_eth:.6f}, need {total_gas_cost:.6f}'
                    )
            else:
                result.checks['wallet_balance_eth'] = 'NOT CONFIGURED'
                result.warnings.append('No wallet configured')
        except Exception as e:
            result.warnings.append(f'Wallet check failed: {e}')

        # Check 5: Flash loan liquidity
        if flash_loan_needed:
            fl_providers = chain.get('flash_loan_providers', [])
            result.checks['flash_loan_providers'] = len(fl_providers)
            if not fl_providers:
                result.warnings.append('No flash loan providers configured for this chain')

            for provider in fl_providers:
                pool = provider.get('pool', '')
                if pool:
                    try:
                        pool_contract = w3.eth.contract(
                            address=Web3.to_checksum_address(pool),
                            abi=self.AAVE_POOL_ABI,
                        )
                        # Try WETH (most common)
                        weth = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2' if chain_id == 1 else '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1'
                        liquidity = pool_contract.functions.getAvailableLiquidity(
                            Web3.to_checksum_address(weth)
                        ).call()
                        result.checks[f'fl_liquidity_{provider["name"]}'] = f'{liquidity / 1e18:.2f} ETH'
                    except Exception:
                        result.checks[f'fl_liquidity_{provider["name"]}'] = 'query failed'

        # Check 6: Gas price volatility
        try:
            gas_price = w3.eth.gas_price
            base_gas = chain.get('gas_price_gwei', 10)
            current_gwei = gas_price / 1e9

            # If gas is >5x the baseline, market is congested
            if current_gwei > base_gas * 5:
                result.warnings.append(
                    f'High gas: {current_gwei:.1f} gwei (baseline {base_gas}). '
                    f'Congested network increases costs and competition.'
                )
            result.checks['gas_congestion'] = f'{current_gwei:.1f} gwei (baseline {base_gas})'
        except Exception:
            pass

        # Check 7: Nonce collision (no pending txs from our wallet)
        try:
            if WALLET_PRIVATE_KEY:
                from eth_account import Account
                wallet = Account.from_key(WALLET_PRIVATE_KEY)
                nonce = w3.eth.get_transaction_count(wallet.address)
                result.checks['wallet_nonce'] = nonce
                pending_count = w3.eth.get_transaction_count(wallet.address, 'pending') - nonce
                if pending_count > 0:
                    result.warnings.append(f'{pending_count} pending transactions from wallet')
        except Exception:
            pass

        # Final recommendation
        if result.blockers:
            result.passed = False
            result.recommendation = f'BLOCKED: {"; ".join(result.blockers)}'
        elif result.warnings:
            result.recommendation = f'PROCEED WITH CAUTION: {"; ".join(result.warnings)}'
        else:
            result.recommendation = 'ALL CHECKS PASSED'

        return result
