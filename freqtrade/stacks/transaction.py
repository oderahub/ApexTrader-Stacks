"""
Stacks transaction builder and signer for contract calls.
Implements the Stacks transaction binary format for mainnet deployment.
"""

import hashlib
import logging
from typing import Optional

try:
    from ecdsa import SECP256k1, SigningKey, VerifyingKey
    from ecdsa.util import sigencode_string, sigdecode_string
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False

from freqtrade.stacks.clarity import c32_decode

logger = logging.getLogger(__name__)


# Transaction version bytes
TX_VERSION_MAINNET = 0x00
TX_VERSION_TESTNET = 0x80

# Chain IDs
CHAIN_ID_MAINNET = 0x00000001
CHAIN_ID_TESTNET = 0x80000000

# Anchor modes
ANCHOR_MODE_ON_CHAIN_ONLY = 0x01
ANCHOR_MODE_OFF_CHAIN_ONLY = 0x02
ANCHOR_MODE_ANY = 0x03

# Post condition modes
POST_CONDITION_ALLOW = 0x01
POST_CONDITION_DENY = 0x02

# Payload types
PAYLOAD_TOKEN_TRANSFER = 0x00
PAYLOAD_CONTRACT_CALL = 0x02
PAYLOAD_SMART_CONTRACT = 0x01
PAYLOAD_POISON_MICROBLOCK = 0x03
PAYLOAD_COINBASE = 0x04

# Authorization types
AUTH_TYPE_STANDARD = 0x04
AUTH_TYPE_SPONSORED = 0x05

# Hash modes for single-sig
HASH_MODE_P2PKH = 0x00  # Single-sig, pay to public key hash
HASH_MODE_P2SH = 0x01   # Multi-sig, pay to script hash
HASH_MODE_P2WPKH = 0x02
HASH_MODE_P2WSH = 0x03

# Signature types
SIGNATURE_RECOVERABLE = 0x00

# Default fee (in microSTX)
DEFAULT_FEE = 10000  # 0.01 STX


def sha512_256(data: bytes) -> bytes:
    """
    Compute SHA512/256 hash (first 32 bytes of SHA512).
    This is the hash function used by Stacks for transaction signing.

    :param data: Data to hash
    :return: 32-byte hash
    """
    full_hash = hashlib.sha512(data).digest()
    return full_hash[:32]


class TransactionSigner:
    """
    Signs Stacks transactions using ECDSA secp256k1.
    """

    def __init__(self, private_key_hex: str):
        """
        Initialize signer with private key.

        :param private_key_hex: 64-character hex private key
        :raises ImportError: If ecdsa library is not installed
        :raises ValueError: If private key format is invalid
        """
        if not ECDSA_AVAILABLE:
            raise ImportError(
                "ecdsa library required for transaction signing. "
                "Install with: pip install ecdsa>=0.18.0"
            )

        # Clean up the key (remove 0x prefix if present)
        key_hex = private_key_hex.strip()
        if key_hex.startswith('0x'):
            key_hex = key_hex[2:]

        # Handle compressed key format (66 chars with 01 suffix)
        if len(key_hex) == 66 and key_hex.endswith('01'):
            key_hex = key_hex[:-2]

        if len(key_hex) != 64:
            raise ValueError(
                f"Private key must be 64 hex characters, got {len(key_hex)}"
            )

        try:
            key_bytes = bytes.fromhex(key_hex)
            self._signing_key = SigningKey.from_string(key_bytes, curve=SECP256k1)
            self._public_key = self._signing_key.get_verifying_key()
        except Exception as e:
            raise ValueError(f"Invalid private key: {e}")

    @property
    def public_key_bytes(self) -> bytes:
        """Get compressed public key (33 bytes)."""
        vk = self._public_key
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()

        # Compressed format: 0x02/0x03 prefix + x coordinate
        prefix = 0x02 if y % 2 == 0 else 0x03
        return bytes([prefix]) + x.to_bytes(32, byteorder='big')

    @property
    def public_key_uncompressed(self) -> bytes:
        """Get uncompressed public key (65 bytes)."""
        return b'\x04' + self._public_key.to_string()

    def sign(self, message_hash: bytes) -> bytes:
        """
        Sign a message hash and return recoverable signature.

        :param message_hash: 32-byte message hash to sign
        :return: 65-byte signature (r[32] + s[32] + recovery_id[1])
        """
        if len(message_hash) != 32:
            raise ValueError(f"Message hash must be 32 bytes, got {len(message_hash)}")

        # Sign the hash
        signature = self._signing_key.sign_digest(
            message_hash,
            sigencode=sigencode_string
        )

        # Extract r and s from signature (each 32 bytes)
        r = int.from_bytes(signature[:32], byteorder='big')
        s = int.from_bytes(signature[32:], byteorder='big')

        # Ensure low-S value (BIP-62)
        order = SECP256k1.order
        if s > order // 2:
            s = order - s

        # Find recovery id (0-3)
        recovery_id = self._find_recovery_id(message_hash, r, s)

        # Return r + s + recovery_id
        return (r.to_bytes(32, byteorder='big') +
                s.to_bytes(32, byteorder='big') +
                bytes([recovery_id]))

    def _find_recovery_id(self, message_hash: bytes, r: int, s: int) -> int:
        """
        Find the recovery ID for the signature.
        Tests recovery IDs 0-3 to find which recovers to our public key.
        """
        for recovery_id in range(4):
            try:
                # Try to recover public key with this recovery id
                recovered = self._recover_public_key(message_hash, r, s, recovery_id)
                if recovered == self.public_key_uncompressed:
                    return recovery_id
            except Exception:
                continue
        # Default to 0 if we can't determine
        return 0

    def _recover_public_key(self, message_hash: bytes, r: int, s: int,
                            recovery_id: int) -> bytes:
        """Attempt to recover public key from signature components."""
        from ecdsa.numbertheory import inverse_mod

        curve = SECP256k1.curve
        generator = SECP256k1.generator
        order = SECP256k1.order

        # Calculate x coordinate
        x = r + (recovery_id // 2) * order

        # Check if x is valid
        if x >= curve.p():
            raise ValueError("Invalid recovery_id")

        # Calculate y^2 = x^3 + ax + b (mod p)
        y_squared = (pow(x, 3, curve.p()) + curve.a() * x + curve.b()) % curve.p()

        # Calculate y using modular square root
        y = pow(y_squared, (curve.p() + 1) // 4, curve.p())

        # Choose correct y based on recovery_id parity
        if (y % 2) != (recovery_id % 2):
            y = curve.p() - y

        # Create point R
        from ecdsa.ellipticcurve import Point
        R = Point(curve, x, y)

        # Recover public key: Q = r^-1 * (s*R - e*G)
        e = int.from_bytes(message_hash, byteorder='big')
        r_inv = inverse_mod(r, order)

        # Calculate s*R
        sR = R * s

        # Calculate e*G
        eG = generator * e

        # Calculate Q = r^-1 * (s*R - e*G)
        Q = (sR + (generator * (order - e))) * r_inv

        # Return uncompressed public key
        return (b'\x04' +
                Q.x().to_bytes(32, byteorder='big') +
                Q.y().to_bytes(32, byteorder='big'))


class StacksTransaction:
    """
    Builds and serializes Stacks transactions.
    """

    def __init__(
        self,
        network: str = "mainnet",
        nonce: int = 0,
        fee: int = DEFAULT_FEE,
        anchor_mode: int = ANCHOR_MODE_ANY,
        post_condition_mode: int = POST_CONDITION_ALLOW,
    ):
        """
        Initialize transaction builder.

        :param network: 'mainnet' or 'testnet'
        :param nonce: Account nonce for this transaction
        :param fee: Fee in microSTX
        :param anchor_mode: Anchor mode (default: any)
        :param post_condition_mode: Post condition mode (default: allow)
        """
        self.network = network
        self.nonce = nonce
        self.fee = fee
        self.anchor_mode = anchor_mode
        self.post_condition_mode = post_condition_mode

        self._payload: Optional[bytes] = None
        self._auth: Optional[bytes] = None

        # Network-specific values
        if network == "mainnet":
            self._version = TX_VERSION_MAINNET
            self._chain_id = CHAIN_ID_MAINNET
        else:
            self._version = TX_VERSION_TESTNET
            self._chain_id = CHAIN_ID_TESTNET

    def set_contract_call_payload(
        self,
        contract_address: str,
        contract_name: str,
        function_name: str,
        function_args: list[bytes],
    ) -> "StacksTransaction":
        """
        Set payload for a contract call.

        :param contract_address: Contract deployer address
        :param contract_name: Contract name
        :param function_name: Function to call
        :param function_args: List of Clarity-encoded arguments
        :return: self for chaining
        """
        # Decode contract address
        version, hash160 = c32_decode(contract_address)

        # Contract name as length-prefixed string
        name_bytes = contract_name.encode('ascii')
        contract_name_encoded = bytes([len(name_bytes)]) + name_bytes

        # Function name as length-prefixed string
        func_bytes = function_name.encode('ascii')
        function_name_encoded = bytes([len(func_bytes)]) + func_bytes

        # Number of arguments (4 bytes, big-endian)
        num_args = len(function_args)

        # Build payload
        payload = bytes([PAYLOAD_CONTRACT_CALL])

        # Contract address (version + hash160)
        payload += bytes([version]) + hash160

        # Contract name
        payload += contract_name_encoded

        # Function name
        payload += function_name_encoded

        # Arguments
        payload += num_args.to_bytes(4, byteorder='big')
        for arg in function_args:
            payload += arg

        self._payload = payload
        return self

    def _serialize_without_auth(self) -> bytes:
        """
        Serialize transaction without auth section for signing.
        """
        if self._payload is None:
            raise ValueError("No payload set")

        result = b''

        # Version (1 byte)
        result += bytes([self._version])

        # Chain ID (4 bytes)
        result += self._chain_id.to_bytes(4, byteorder='big')

        # Auth placeholder (will be filled during signing)
        # For initial sighash, we use empty spending conditions
        result += bytes([AUTH_TYPE_STANDARD])
        result += bytes([HASH_MODE_P2PKH])

        # Placeholder for signer (20 bytes of zeros)
        result += bytes(20)

        # Nonce (8 bytes)
        result += self.nonce.to_bytes(8, byteorder='big')

        # Fee (8 bytes)
        result += self.fee.to_bytes(8, byteorder='big')

        # Origin spending condition (just hash mode again for standard auth)
        # Empty signature placeholder (65 bytes: type + signature)
        result += bytes([SIGNATURE_RECOVERABLE]) + bytes(65)

        # Anchor mode (1 byte)
        result += bytes([self.anchor_mode])

        # Post-condition mode (1 byte)
        result += bytes([self.post_condition_mode])

        # Post-conditions length (4 bytes) - empty for now
        result += (0).to_bytes(4, byteorder='big')

        # Payload
        result += self._payload

        return result

    def get_sighash(self, signer_public_key: bytes) -> bytes:
        """
        Get the signing hash for this transaction.

        :param signer_public_key: Compressed public key (33 bytes)
        :return: 32-byte hash to sign
        """
        if self._payload is None:
            raise ValueError("No payload set")

        # Build initial sighash input
        result = b''

        # Version (1 byte)
        result += bytes([self._version])

        # Chain ID (4 bytes)
        result += self._chain_id.to_bytes(4, byteorder='big')

        # Auth type
        result += bytes([AUTH_TYPE_STANDARD])

        # Hash mode
        result += bytes([HASH_MODE_P2PKH])

        # Signer: hash160 of public key
        signer_hash = hashlib.new('ripemd160',
                                  hashlib.sha256(signer_public_key).digest()).digest()
        result += signer_hash

        # Nonce (8 bytes)
        result += self.nonce.to_bytes(8, byteorder='big')

        # Fee (8 bytes)
        result += self.fee.to_bytes(8, byteorder='big')

        # Spending condition type (just hash mode byte for P2PKH)
        # For the presign hash, we include the signature type placeholder
        result += bytes([SIGNATURE_RECOVERABLE])

        # Anchor mode (1 byte)
        result += bytes([self.anchor_mode])

        # Post-condition mode (1 byte)
        result += bytes([self.post_condition_mode])

        # Post-conditions length (4 bytes) - empty
        result += (0).to_bytes(4, byteorder='big')

        # Payload
        result += self._payload

        # Compute SHA512/256
        return sha512_256(result)

    def sign(self, signer: TransactionSigner) -> bytes:
        """
        Sign the transaction and return serialized signed transaction.

        :param signer: TransactionSigner instance with private key
        :return: Fully signed, serialized transaction bytes
        """
        if self._payload is None:
            raise ValueError("No payload set")

        public_key = signer.public_key_bytes

        # Get sighash and sign it
        sighash = self.get_sighash(public_key)
        signature = signer.sign(sighash)

        # Build final signed transaction
        result = b''

        # Version (1 byte)
        result += bytes([self._version])

        # Chain ID (4 bytes)
        result += self._chain_id.to_bytes(4, byteorder='big')

        # Authorization section
        result += bytes([AUTH_TYPE_STANDARD])
        result += bytes([HASH_MODE_P2PKH])

        # Signer: hash160 of public key
        signer_hash = hashlib.new('ripemd160',
                                  hashlib.sha256(public_key).digest()).digest()
        result += signer_hash

        # Nonce (8 bytes)
        result += self.nonce.to_bytes(8, byteorder='big')

        # Fee (8 bytes)
        result += self.fee.to_bytes(8, byteorder='big')

        # Signature (recoverable type + 65 bytes)
        result += bytes([SIGNATURE_RECOVERABLE])
        result += signature

        # Anchor mode (1 byte)
        result += bytes([self.anchor_mode])

        # Post-condition mode (1 byte)
        result += bytes([self.post_condition_mode])

        # Post-conditions length (4 bytes) - empty
        result += (0).to_bytes(4, byteorder='big')

        # Payload
        result += self._payload

        return result

    def serialize_hex(self, signer: TransactionSigner) -> str:
        """
        Sign and serialize transaction to hex string.

        :param signer: TransactionSigner instance
        :return: Hex-encoded signed transaction
        """
        return self.sign(signer).hex()


def build_contract_call_transaction(
    contract_id: str,
    function_name: str,
    function_args: list[bytes],
    nonce: int,
    fee: int = DEFAULT_FEE,
    network: str = "mainnet",
) -> StacksTransaction:
    """
    Build a contract call transaction.

    :param contract_id: Contract identifier (e.g., 'SP2FY...FYG.contract-name')
    :param function_name: Function to call
    :param function_args: List of Clarity-encoded arguments
    :param nonce: Account nonce
    :param fee: Fee in microSTX
    :param network: 'mainnet' or 'testnet'
    :return: Unsigned StacksTransaction
    """
    parts = contract_id.split('.')
    if len(parts) != 2:
        raise ValueError(f"Invalid contract_id format: {contract_id}")

    contract_address = parts[0]
    contract_name = parts[1]

    tx = StacksTransaction(network=network, nonce=nonce, fee=fee)
    tx.set_contract_call_payload(
        contract_address=contract_address,
        contract_name=contract_name,
        function_name=function_name,
        function_args=function_args,
    )
    return tx


def estimate_fee(tx_size_bytes: int, fee_rate: int = 1) -> int:
    """
    Estimate transaction fee based on size.

    :param tx_size_bytes: Transaction size in bytes
    :param fee_rate: Fee rate in microSTX per byte
    :return: Estimated fee in microSTX
    """
    # Base fee + size-based fee
    base_fee = 1000  # 0.001 STX minimum
    size_fee = tx_size_bytes * fee_rate
    return max(base_fee, size_fee)
