"""
Escrow contract interaction manager for ApexTrader-Stacks.
Handles deposits, withdrawals, and trade approvals.
"""

import logging
from typing import Any, Optional

from freqtrade.stacks.client import StacksClient
from freqtrade.stacks.clarity import (
    encode_uint128,
    encode_int128,
    encode_string_ascii,
    encode_principal,
)

logger = logging.getLogger(__name__)

# Default transaction fee in microSTX (0.01 STX)
DEFAULT_TX_FEE = 10000


class EscrowManager:
    """
    Manages interactions with the USDCx escrow smart contract.
    """

    def __init__(self, stacks_client: StacksClient):
        """
        Initialize escrow manager.

        :param stacks_client: Configured StacksClient instance
        """
        self.client = stacks_client
        self.contract_id = stacks_client.contract_address
        self.dry_run = stacks_client.config.get("dry_run", True)

        # Track mock balances for dry-run mode
        self._mock_balance: float = 0.0
        self._mock_trades: dict[int, dict] = {}
        self._mock_trade_counter: int = 1

        logger.info(
            f"EscrowManager initialized: contract={self.contract_id}, "
            f"dry_run={self.dry_run}"
        )

    def _parse_clarity_uint(self, result: dict) -> int:
        """
        Parse a Clarity uint response.

        :param result: API response from read-only call
        :return: Integer value
        """
        if not result.get("okay"):
            return 0

        # Clarity values are returned in a specific format
        # Example: {"okay": true, "result": "0x0100000000000000000000000000000064"}
        hex_value = result.get("result", "0x00")

        try:
            # Remove '0x01' prefix (indicates uint type) and convert
            if hex_value.startswith("0x01"):
                return int(hex_value[4:], 16)
            elif hex_value.startswith("0x"):
                return int(hex_value[2:], 16)
            return int(hex_value, 16)
        except (ValueError, TypeError):
            return 0

    def get_escrow_balance(self, user_address: str | None = None) -> float:
        """
        Get user's balance in escrow contract.

        :param user_address: Address to check (defaults to wallet)
        :return: Balance in STX
        """
        if self.dry_run:
            return self._mock_balance

        address = user_address or self.client.wallet_address
        if not address:
            return 0.0

        try:
            # Encode principal as Clarity argument
            # Principal encoding: 0x05 + 1-byte version + 20-byte hash
            # For simplicity in MVP, we pass the address string
            result = self.client.call_read_only(
                function_name="get-balance",
                arguments=[self._encode_principal(address)],
            )
            micro_stx = self._parse_clarity_uint(result)
            return micro_stx / 1_000_000
        except Exception as e:
            logger.error(f"Error fetching escrow balance: {e}")
            return 0.0

    def _encode_principal(self, address: str) -> str:
        """
        Encode a principal address for Clarity.
        For MVP, we use a simplified encoding.

        :param address: Stacks address
        :return: Hex-encoded Clarity principal
        """
        # Standard principal encoding
        # In production, use proper Clarity serialization
        # For now, return hex representation
        return f"0x05{address.encode().hex()}"

    def is_bot_authorized(self, bot_address: str | None = None) -> bool:
        """
        Check if bot address is authorized in escrow contract.

        :param bot_address: Address to check (defaults to wallet)
        :return: True if authorized
        """
        if self.dry_run:
            return True  # Always authorized in dry-run

        address = bot_address or self.client.wallet_address
        try:
            result = self.client.call_read_only(
                function_name="is-bot-authorized",
                arguments=[self._encode_principal(address)],
            )
            return result.get("okay", False) and result.get("result") == "0x03"  # true
        except Exception as e:
            logger.error(f"Error checking bot authorization: {e}")
            return False

    def request_trade_approval(
        self,
        amount: float,
        trade_id: str,
        expiry_blocks: int = 100,
    ) -> str | None:
        """
        Request approval for a trade from the escrow contract.

        :param amount: Trade amount in STX
        :param trade_id: External trade identifier
        :param expiry_blocks: Blocks until approval expires
        :return: Transaction ID if successful, None otherwise
        """
        logger.info(
            f"Requesting trade approval: amount={amount}, "
            f"trade_id={trade_id}, expiry={expiry_blocks}"
        )

        if amount <= 0:
            logger.error(f"Invalid trade amount: {amount}")
            return None

        if self.dry_run:
            # Mock the trade approval
            mock_id = self._mock_trade_counter
            self._mock_trades[mock_id] = {
                "amount": amount,
                "external_id": trade_id,
                "expiry_blocks": expiry_blocks,
                "executed": False,
            }
            self._mock_trade_counter += 1
            tx_id = self.client.generate_mock_tx_id(f"approve-{mock_id}")
            logger.info(f"[DRY-RUN] Trade approval mock tx: {tx_id}")
            return tx_id

        # Production: build and broadcast trade approval transaction
        try:
            # Check if contract is paused
            if self.is_paused():
                logger.error("Cannot request trade approval: contract is paused")
                return None

            # Convert STX to microSTX
            micro_stx = int(amount * 1_000_000)

            # Build arguments:
            # - amount: uint128
            # - trade_id: string-ascii (external identifier)
            # - expiry_blocks: uint128
            args = [
                encode_uint128(micro_stx),
                encode_string_ascii(trade_id),
                encode_uint128(expiry_blocks),
            ]

            # Sign and broadcast
            tx_id = self.client.sign_and_broadcast(
                contract_id=self.contract_id,
                function_name="request-trade",
                function_args=args,
            )

            logger.info(f"Trade approval transaction broadcast: {tx_id}")
            return tx_id

        except Exception as e:
            logger.error(f"Error requesting trade approval: {e}")
            return None

    def execute_trade(
        self,
        trade_id: int,
        profit_loss: float,
    ) -> str | None:
        """
        Execute a trade after it fills, updating escrow balance.

        :param trade_id: Contract trade ID
        :param profit_loss: Profit (positive) or loss (negative) in STX
        :return: Transaction ID if successful, None otherwise
        """
        logger.info(f"Executing trade: id={trade_id}, P/L={profit_loss}")

        if self.dry_run:
            # Update mock balance
            self._mock_balance += profit_loss
            if self._mock_balance < 0:
                self._mock_balance = 0

            # Mark trade as executed
            if trade_id in self._mock_trades:
                self._mock_trades[trade_id]["executed"] = True

            tx_id = self.client.generate_mock_tx_id(f"execute-{trade_id}")
            logger.info(
                f"[DRY-RUN] Trade executed. New balance: {self._mock_balance}, "
                f"tx: {tx_id}"
            )
            return tx_id

        # Production: build and broadcast execute trade transaction
        try:
            # Check if contract is paused
            if self.is_paused():
                logger.error("Cannot execute trade: contract is paused")
                return None

            # Convert P/L to microSTX (signed)
            micro_stx_pl = int(profit_loss * 1_000_000)

            # Build arguments:
            # - trade_id: uint128
            # - profit_loss: int128 (signed value)
            args = [
                encode_uint128(trade_id),
                encode_int128(micro_stx_pl),
            ]

            # Sign and broadcast
            tx_id = self.client.sign_and_broadcast(
                contract_id=self.contract_id,
                function_name="execute-trade",
                function_args=args,
            )

            logger.info(f"Trade execution transaction broadcast: {tx_id}")
            return tx_id

        except Exception as e:
            logger.error(f"Error executing trade: {e}")
            return None

    def deposit(self, amount: float) -> str | None:
        """
        Deposit STX into escrow contract.

        :param amount: Amount in STX to deposit
        :return: Transaction ID if successful
        """
        logger.info(f"Depositing to escrow: {amount} STX")

        if amount <= 0:
            logger.error(f"Invalid deposit amount: {amount}")
            return None

        if self.dry_run:
            self._mock_balance += amount
            tx_id = self.client.generate_mock_tx_id("deposit")
            logger.info(
                f"[DRY-RUN] Deposit complete. Balance: {self._mock_balance}, "
                f"tx: {tx_id}"
            )
            return tx_id

        # Production: build and broadcast deposit transaction
        try:
            # Check if contract is paused
            if self.is_paused():
                logger.error("Cannot deposit: contract is paused")
                return None

            # Convert STX to microSTX
            micro_stx = int(amount * 1_000_000)

            # Build argument: amount as uint128
            args = [encode_uint128(micro_stx)]

            # Sign and broadcast
            tx_id = self.client.sign_and_broadcast(
                contract_id=self.contract_id,
                function_name="deposit",
                function_args=args,
            )

            logger.info(f"Deposit transaction broadcast: {tx_id}")
            return tx_id

        except Exception as e:
            logger.error(f"Error depositing to escrow: {e}")
            return None

    def withdraw(self, amount: float) -> str | None:
        """
        Withdraw STX from escrow contract.

        :param amount: Amount in STX to withdraw
        :return: Transaction ID if successful
        """
        logger.info(f"Withdrawing from escrow: {amount} STX")

        if amount <= 0:
            logger.error(f"Invalid withdrawal amount: {amount}")
            return None

        if self.dry_run:
            if amount > self._mock_balance:
                logger.error(
                    f"Insufficient balance: {self._mock_balance} < {amount}"
                )
                return None
            self._mock_balance -= amount
            tx_id = self.client.generate_mock_tx_id("withdraw")
            logger.info(
                f"[DRY-RUN] Withdrawal complete. Balance: {self._mock_balance}, "
                f"tx: {tx_id}"
            )
            return tx_id

        # Production: build and broadcast withdraw transaction
        try:
            # Check if contract is paused
            if self.is_paused():
                logger.error("Cannot withdraw: contract is paused")
                return None

            # Convert STX to microSTX
            micro_stx = int(amount * 1_000_000)

            # Build argument: amount as uint128
            args = [encode_uint128(micro_stx)]

            # Sign and broadcast
            tx_id = self.client.sign_and_broadcast(
                contract_id=self.contract_id,
                function_name="withdraw",
                function_args=args,
            )

            logger.info(f"Withdrawal transaction broadcast: {tx_id}")
            return tx_id

        except Exception as e:
            logger.error(f"Error withdrawing from escrow: {e}")
            return None

    def get_trade(self, trade_id: int) -> dict | None:
        """
        Get trade details from contract.

        :param trade_id: Trade ID
        :return: Trade details or None
        """
        if self.dry_run:
            return self._mock_trades.get(trade_id)

        try:
            result = self.client.call_read_only(
                function_name="get-trade",
                arguments=[f"0x01{trade_id:016x}"],  # uint encoding
            )
            if result.get("okay"):
                return result.get("result")
            return None
        except Exception as e:
            logger.error(f"Error fetching trade: {e}")
            return None

    def is_paused(self) -> bool:
        """Check if contract is paused."""
        if self.dry_run:
            return False

        try:
            result = self.client.call_read_only(function_name="is-paused")
            return result.get("okay", False) and result.get("result") == "0x03"
        except Exception as e:
            logger.error(f"Error checking pause status: {e}")
            return False

    def get_status(self) -> dict:
        """Get escrow manager status."""
        return {
            "contract_id": self.contract_id,
            "dry_run": self.dry_run,
            "balance": self.get_escrow_balance(),
            "is_configured": self.client.is_configured(),
            "network": self.client.network,
        }
