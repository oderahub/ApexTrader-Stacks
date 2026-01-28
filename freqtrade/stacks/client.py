"""
Stacks blockchain client for ApexTrader-Stacks.
Handles wallet operations and transaction management.
"""

import hashlib
import logging
from typing import Any, Optional

from freqtrade.stacks.hiro_api import HiroAPI

logger = logging.getLogger(__name__)

# Default transaction fee in microSTX
DEFAULT_FEE = 10000  # 0.01 STX
MAX_FEE = 1000000    # 1 STX maximum to prevent accidents


class StacksClient:
    """
    Client for interacting with Stacks blockchain.
    Wraps Hiro API and provides wallet/transaction functionality.
    """

    def __init__(self, config: dict):
        """
        Initialize Stacks client from Freqtrade config.

        Supports two authentication methods:
        1. seed_phrase: BIP39 mnemonic (recommended)
        2. private_key: Raw hex private key (legacy)

        :param config: Freqtrade configuration dict
        """
        self.config = config
        stacks_config = config.get("stacks", {})
        exchange_config = config.get("exchange", {})

        self.network = stacks_config.get("network", "testnet")
        self.contract_address = stacks_config.get("escrow_contract", "")

        # Initialize wallet from seed phrase or private key
        self._wallet = None
        self._private_key: str = ""
        self.wallet_address = exchange_config.get("wallet_address", "")

        # Try seed phrase first (preferred method)
        seed_phrase = exchange_config.get("seed_phrase", "")
        if seed_phrase:
            self._init_from_seed_phrase(
                seed_phrase=seed_phrase,
                passphrase=exchange_config.get("seed_passphrase", ""),
                account_index=exchange_config.get("account_index", 0),
            )
        elif exchange_config.get("private_key"):
            # Fallback to raw private key
            self._private_key = exchange_config.get("private_key", "")
            logger.warning(
                "Using raw private key. Consider using seed_phrase instead."
            )

        # Initialize Hiro API
        self.api = HiroAPI(
            network=self.network,
            api_key=stacks_config.get("hiro_api_key"),
        )

        addr_display = self.wallet_address[:20] if self.wallet_address else "not set"
        logger.info(
            f"StacksClient initialized: network={self.network}, "
            f"wallet={addr_display}..."
        )

    def _init_from_seed_phrase(
        self,
        seed_phrase: str,
        passphrase: str = "",
        account_index: int = 0,
    ) -> None:
        """
        Initialize wallet from BIP39 seed phrase.

        :param seed_phrase: BIP39 mnemonic
        :param passphrase: Optional BIP39 passphrase
        :param account_index: Account index for derivation
        """
        try:
            from freqtrade.stacks.wallet import StacksWallet

            self._wallet = StacksWallet(
                seed_phrase=seed_phrase,
                passphrase=passphrase,
                network=self.network,
                account_index=account_index,
            )
            self.wallet_address = self._wallet.address
            self._private_key = self._wallet.private_key_hex
            logger.info(f"Wallet derived from seed phrase: {self.wallet_address[:20]}...")

        except ImportError as e:
            logger.error(
                f"Cannot derive wallet from seed phrase: {e}. "
                "Install with: pip install mnemonic>=0.20"
            )
        except Exception as e:
            logger.error(f"Failed to derive wallet from seed phrase: {e}")

    def get_stx_balance(self) -> float:
        """
        Get wallet STX balance in STX (not microSTX).

        :return: Balance in STX
        """
        if not self.wallet_address:
            return 0.0
        micro_stx = self.api.get_stx_balance(self.wallet_address)
        return micro_stx / 1_000_000

    def get_account_balances(self) -> dict:
        """
        Get all balances for wallet.

        :return: Balance dict with STX and tokens
        """
        if not self.wallet_address:
            return {}
        return self.api.get_account_balances(self.wallet_address)

    def get_nonce(self) -> int:
        """
        Get current account nonce for transaction building.

        :return: Account nonce
        """
        if not self.wallet_address:
            return 0
        account_info = self.api.get_account_info(self.wallet_address)
        return int(account_info.get("nonce", 0))

    def get_block_height(self) -> int:
        """Get current Stacks block height."""
        return self.api.get_block_height()

    def call_read_only(
        self,
        function_name: str,
        arguments: list[str] | None = None,
        contract_id: str | None = None,
    ) -> dict:
        """
        Call a read-only contract function.

        :param function_name: Function name
        :param arguments: Clarity-encoded arguments
        :param contract_id: Optional contract ID (defaults to escrow contract)
        :return: Function result
        """
        target_contract = contract_id or self.contract_address
        if not target_contract:
            raise ValueError("No contract address configured")

        return self.api.call_read_only(
            contract_id=target_contract,
            function_name=function_name,
            arguments=arguments,
            sender=self.wallet_address,
        )

    def get_transaction_status(self, tx_id: str) -> str:
        """
        Get transaction status.

        :param tx_id: Transaction ID
        :return: Status string
        """
        return self.api.get_transaction_status(tx_id)

    def broadcast_transaction(self, signed_tx_hex: str) -> str:
        """
        Broadcast a signed transaction.

        :param signed_tx_hex: Hex-encoded signed transaction
        :return: Transaction ID
        """
        result = self.api.broadcast_transaction(signed_tx_hex)
        tx_id = result.get("txid", "")
        logger.info(f"Transaction broadcast: {tx_id}")
        return tx_id

    def generate_mock_tx_id(self, prefix: str = "mock") -> str:
        """
        Generate a mock transaction ID for dry-run mode.

        :param prefix: Prefix for the mock ID
        :return: Mock transaction ID
        """
        import time

        data = f"{prefix}-{self.wallet_address}-{time.time()}"
        hash_hex = hashlib.sha256(data.encode()).hexdigest()
        return f"0x{hash_hex[:64]}"

    def is_configured(self) -> bool:
        """Check if client is properly configured."""
        return bool(self.wallet_address and self.contract_address)

    def get_network_info(self) -> dict:
        """Get network configuration info."""
        return {
            "network": self.network,
            "wallet_address": self.wallet_address,
            "contract_address": self.contract_address,
            "api_base_url": self.api.base_url,
        }

    def has_private_key(self) -> bool:
        """Check if private key is configured (from seed phrase or directly)."""
        return bool(self._private_key)

    def get_transaction_signer(self) -> "TransactionSigner":
        """
        Get a TransactionSigner instance for this client.

        :return: TransactionSigner configured with the client's private key
        :raises ValueError: If no private key is configured
        """
        if self._wallet:
            return self._wallet.get_signer()

        if not self._private_key:
            raise ValueError(
                "No private key configured. Add seed_phrase to exchange config."
            )

        from freqtrade.stacks.transaction import TransactionSigner
        return TransactionSigner(self._private_key)

    def sign_and_broadcast(
        self,
        contract_id: str,
        function_name: str,
        function_args: list[bytes],
        fee: Optional[int] = None,
    ) -> str:
        """
        Build, sign, and broadcast a contract call transaction.

        :param contract_id: Contract identifier (e.g., 'SP2FY...FYG.contract-name')
        :param function_name: Function to call
        :param function_args: List of Clarity-encoded arguments
        :param fee: Optional fee in microSTX (default: DEFAULT_FEE)
        :return: Transaction ID
        :raises ValueError: If private key not configured or fee too high
        """
        from freqtrade.stacks.transaction import (
            build_contract_call_transaction,
            TransactionSigner,
        )

        if not self._private_key:
            raise ValueError(
                "Cannot sign transaction: no private key configured. "
                "Add seed_phrase to exchange config."
            )

        # Get current nonce
        nonce = self.get_nonce()

        # Validate and set fee
        tx_fee = fee if fee is not None else DEFAULT_FEE
        if tx_fee > MAX_FEE:
            raise ValueError(
                f"Fee {tx_fee} exceeds maximum allowed {MAX_FEE} microSTX"
            )

        # Build transaction
        tx = build_contract_call_transaction(
            contract_id=contract_id,
            function_name=function_name,
            function_args=function_args,
            nonce=nonce,
            fee=tx_fee,
            network=self.network,
        )

        # Sign transaction
        signer = self.get_transaction_signer()
        signed_tx_hex = tx.serialize_hex(signer)

        logger.info(
            f"Signing transaction: contract={contract_id}, "
            f"function={function_name}, nonce={nonce}, fee={tx_fee}"
        )

        # Broadcast
        tx_id = self.broadcast_transaction(signed_tx_hex)
        return tx_id

    def estimate_fee(self, tx_size_bytes: int = 500) -> int:
        """
        Estimate fee for a transaction.

        :param tx_size_bytes: Estimated transaction size
        :return: Estimated fee in microSTX
        """
        from freqtrade.stacks.transaction import estimate_fee
        return estimate_fee(tx_size_bytes)
