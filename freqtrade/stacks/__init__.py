"""
Stacks blockchain integration module for ApexTrader-Stacks.
Provides client interfaces for Hiro API and escrow contract management.
"""

from freqtrade.stacks.client import StacksClient
from freqtrade.stacks.escrow import EscrowManager
from freqtrade.stacks.hiro_api import HiroAPI

__all__ = ["StacksClient", "EscrowManager", "HiroAPI"]

# Transaction signing components (optional, require ecdsa library)
try:
    from freqtrade.stacks.transaction import (
        StacksTransaction,
        TransactionSigner,
        build_contract_call_transaction,
    )
    from freqtrade.stacks.clarity import (
        encode_uint128,
        encode_int128,
        encode_bool,
        encode_principal,
        encode_buff,
        encode_string_ascii,
        clarity_value_to_hex,
    )
    __all__.extend([
        "StacksTransaction",
        "TransactionSigner",
        "build_contract_call_transaction",
        "encode_uint128",
        "encode_int128",
        "encode_bool",
        "encode_principal",
        "encode_buff",
        "encode_string_ascii",
        "clarity_value_to_hex",
    ])
except ImportError:
    pass  # Transaction signing not available (ecdsa not installed)

# Wallet components (optional, require mnemonic library)
try:
    from freqtrade.stacks.wallet import (
        StacksWallet,
        derive_stacks_private_key,
        derive_stacks_address,
        validate_mnemonic,
    )
    __all__.extend([
        "StacksWallet",
        "derive_stacks_private_key",
        "derive_stacks_address",
        "validate_mnemonic",
    ])
except ImportError:
    pass  # Wallet derivation not available (mnemonic not installed)
