r"""T3-3 Alert System - Email (Gmail) + Telegram + file logging."""

import json
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from .config import (
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, ALERTS_FILE,
    ALERT_EMAIL, ALERT_EMAIL_PASSWORD, ALERT_EMAIL_TO,
)


class AlertManager:
    def __init__(self):
        self.telegram_enabled = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
        self.email_enabled = bool(ALERT_EMAIL and ALERT_EMAIL_PASSWORD and ALERT_EMAIL_TO)
        if not self.telegram_enabled:
            print('[ALERTS] Telegram not configured')
        if self.email_enabled:
            print(f'[ALERTS] Email alerts ON -> {ALERT_EMAIL_TO}')
        else:
            print('[ALERTS] Email not configured')
        self.session = requests.Session()

    def send_alert(self, alert_type, severity, message, protocol_name='',
                   contract_address='', chain_id=0, finding_ids=None):
        self._log_to_file(alert_type, severity, message, protocol_name,
                          contract_address, chain_id, finding_ids)
        if self.telegram_enabled:
            self._send_telegram(severity, message, protocol_name,
                             contract_address, chain_id)
        if self.email_enabled:
            # Only email CRITICAL/HIGH + exploit results
            if severity in ('CRITICAL', 'HIGH') or alert_type in ('exploit_result', 'exploit_attempt'):
                self._send_email(severity, message, protocol_name,
                                 contract_address, chain_id, alert_type)

    def send_exploit_result(self, success, tx_hash, profit_eth=0, profit_usd=0,
                             target='', chain=''):
        status = 'SUCCESS' if success else 'FAILED'
        msg = f'Exploit {status} | Target: {target} | TX: {tx_hash} | Profit: {profit_eth:.6f} ETH / ${profit_usd:.2f}'
        self.send_alert('exploit_result', 'CRITICAL' if success else 'HIGH', msg)

    def send_scan_summary(self, protocols_scanned, findings_found, critical, high, zero_cap):
        msg = f'Scan: {protocols_scanned} protocols, {findings_found} findings ({critical} crit, {high} high), {zero_cap} zero-cap'
        self.send_alert('scan_summary', 'INFO', msg)

    def _send_email(self, severity, message, protocol_name, contract_address, chain_id, alert_type):
        try:
            ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
            subject = f'[T3-3 {severity}] {alert_type}'
            if protocol_name:
                subject += f' - {protocol_name}'

            body_parts = [f'<h2>[{severity}] {alert_type}</h2>', f'<p>{message}</p>']
            if contract_address and chain_id:
                from .config import CHAINS
                explorer = CHAINS.get(chain_id, {}).get('explorer_url', '')
                if explorer:
                    body_parts.append(f'<p>Contract: <a href="{explorer}/address/{contract_address}">{contract_address}</a></p>')
            if protocol_name:
                body_parts.append(f'<p>Protocol: <b>{protocol_name}</b></p>')
            body_parts.append(f'<p><i>{ts}</i></p>')
            html_body = '\n'.join(body_parts)

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = ALERT_EMAIL
            msg['To'] = ALERT_EMAIL_TO
            msg.attach(MIMEText(html_body, 'html'))

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(ALERT_EMAIL, ALERT_EMAIL_PASSWORD)
                server.send_message(msg)
            print(f'[ALERTS] Email sent: {subject}')
        except Exception as e:
            print(f'[ALERTS] Email error: {e}')

    def _send_telegram(self, severity, message, protocol_name, contract_address, chain_id):
        if len(message) > 4000:
            message = message[:4000] + '...'
        text = f'<b>[{severity}]</b> {message}'
        parts = []
        if contract_address and chain_id:
            from .config import CHAINS
            explorer = CHAINS.get(chain_id, {}).get('explorer_url', '')
            if explorer:
                parts.append(f'<a href="{explorer}/address/{contract_address}">Contract</a>')
        if protocol_name:
            parts.append(f'Protocol: {protocol_name}')
        if parts:
            text += ' | ' + ' | '.join(parts)
        text += f' | <i>{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</i>'
        url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
        try:
            self.session.post(url, json={'chat_id': TELEGRAM_CHAT_ID, 'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True}, timeout=10)
        except Exception as e:
            print(f'[ALERTS] Telegram error: {e}')

    def _log_to_file(self, alert_type, severity, message, protocol_name, contract_address, chain_id, finding_ids=None):
        ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry = {'timestamp': datetime.now(timezone.utc).isoformat(), 'alert_type': alert_type, 'severity': severity, 'message': message, 'protocol_name': protocol_name, 'contract_address': contract_address, 'chain_id': chain_id, 'finding_ids': finding_ids or []}
        with open(ALERTS_FILE, 'a') as f:
            f.write(json.dumps(entry) + chr(10))
