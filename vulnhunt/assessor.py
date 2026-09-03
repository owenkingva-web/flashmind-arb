"""T3-3 Exploitability Assessor

Scores findings for zero-capital feasibility, profit vs gas, competition.
"""

from .config import CHAINS, ETH_PRICE_USD, SEVERITY_ORDER


class ExploitabilityAssessor:
    def assess(self, finding: dict, chain_id: int, tvl: float = 0,
                prober_data: dict = None) -> dict:
        chain = CHAINS.get(chain_id, {})
        gas_gwei = chain.get('gas_price_gwei', 10)
        est_gas = finding.get('estimated_gas', 300000)
        gas_cost_eth = (est_gas * gas_gwei) / 1e9
        gas_cost_usd = gas_cost_eth * ETH_PRICE_USD

        severity = finding.get('severity', 'MEDIUM')
        confidence = finding.get('confidence', 0.5)
        zero_cap = finding.get('zero_capital', False)
        flash = finding.get('flash_loan_required', False)
        category = finding.get('category', '')

        sev_score = {'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 40, 'LOW': 15, 'INFO': 0}
        base_score = sev_score.get(severity, 0)
        zero_cap_mult = 2.0 if zero_cap else 0.3
        conf_mult = 0.5 + (confidence * 0.5)

        if tvl > 1_000_000:
            tvl_mult = 2.0
        elif tvl > 100_000:
            tvl_mult = 1.5
        elif tvl > 10_000:
            tvl_mult = 1.0
        elif tvl > 0:
            tvl_mult = 0.5
        else:
            tvl_mult = 0.3

        if chain_id == 1:
            comp_mult = 0.6
        elif chain_id == 56:
            comp_mult = 0.8
        else:
            comp_mult = 1.0

        cat_bonus = {
            'Reentrancy': 10, 'Access Control': 15,
            'Oracle Manipulation': 10, 'Governance': 15,
            'Selfdestruct': 20, 'Initialization': 20,
            'Unsafe Delegatecall': 15,
        }
        bonus = cat_bonus.get(category, 0)

        raw_score = (base_score * zero_cap_mult * conf_mult * tvl_mult * comp_mult) + bonus
        priority = min(100, int(raw_score))

        if zero_cap and tvl > 0:
            est_profit_low = tvl * 0.01
            est_profit_high = min(tvl * 0.10, 10_000_000)
        else:
            est_profit_low = 0
            est_profit_high = 0

        should_auto_execute = False
        should_alert = False
        action_reason = ''

        # Auto-execute thresholds (ordered so branches are mutually exclusive):
        # 1. High confidence + high priority → AUTO-EXECUTE (safest, most reliable)
        # 2. Medium confidence on-chain confirmed → AUTO-EXECUTE (lower bar for RPC-confirmed state)
        # 3. Moderate confidence but not auto-execute → ALERT for manual review
        # 4. High severity but not zero-cap → ALERT
        if zero_cap and priority >= 70 and confidence >= 0.7:
            should_auto_execute = True
            action_reason = 'AUTO-EXECUTE: High confidence zero-cap exploit'
        elif zero_cap and priority >= 25 and confidence >= 0.4:
            # Lower threshold for on-chain confirmed findings (fast_rpc source)
            should_auto_execute = True
            action_reason = 'AUTO-EXECUTE: On-chain confirmed zero-cap'
        elif zero_cap and priority >= 50 and confidence >= 0.5:
            # Medium quality — alert for manual review, don't auto-execute
            should_alert = True
            action_reason = 'ALERT: Potential zero-cap exploit, needs validation'
        elif severity in ('CRITICAL', 'HIGH') and confidence >= 0.6:
            should_alert = True
            action_reason = 'ALERT: High severity finding'

        if est_profit_low > 0 and gas_cost_usd > 0:
            profit_to_gas = est_profit_low / gas_cost_usd
            profitable = profit_to_gas > 10
        else:
            profit_to_gas = 0
            profitable = False

        if flash:
            if chain_id == 1:
                competition = 'HIGH - Mainnet MEV bots'
            elif chain_id in (42161, 8453):
                competition = 'MEDIUM - L2 MEV growing'
            else:
                competition = 'LOW'
            difficulty = 'Medium - requires flash loan + attacker contract'
        elif zero_cap:
            competition = 'LOW - Direct call, minimal competition'
            difficulty = 'Low - single transaction'
        else:
            competition = 'UNKNOWN'
            difficulty = 'Unknown'

        prober_insights = []
        if prober_data:
            if prober_data.get('is_proxy') and not prober_data.get('implementation'):
                prober_insights.append('UNINITIALIZED PROXY')
            if prober_data.get('governance', {}).get('zero_threshold'):
                prober_insights.append('ZERO PROPOSAL THRESHOLD')
            for role in ['owner', 'admin', 'guardian']:
                if prober_data.get('governance', {}).get(f'{role}_is_eoa'):
                    prober_insights.append(f'{role.upper()} IS EOA')

        return {
            'vuln_id': finding.get('vuln_id', ''),
            'severity': severity, 'category': category,
            'confidence': confidence, 'priority_score': priority,
            'zero_capital': zero_cap, 'flash_loan_required': flash,
            'gas_cost_eth': f'{gas_cost_eth:.6f}',
            'gas_cost_usd': f'${gas_cost_usd:.4f}',
            'est_profit_low': f'${est_profit_low:,.2f}',
            'est_profit_high': f'${est_profit_high:,.2f}',
            'profit_to_gas_ratio': f'{profit_to_gas:,.0f}x',
            'profitable': profitable,
            'competition': competition, 'difficulty': difficulty,
            'should_auto_execute': should_auto_execute,
            'should_alert': should_alert,
            'action_reason': action_reason,
            'prober_insights': prober_insights,
            'tvl': tvl, 'chain_name': chain.get('name', 'unknown'),
        }

    def rank_findings(self, findings):
        return sorted(findings, key=lambda x: x.get('priority_score', 0), reverse=True)
