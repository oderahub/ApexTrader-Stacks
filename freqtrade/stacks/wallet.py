"""
Stacks wallet key derivation from BIP39 seed phrases.
Derives private keys using the Stacks derivation path: m/44'/5757'/0'/0/0
"""

import hashlib
import hmac
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Stacks uses coin type 5757 (0x167D)
# Standard derivation path: m/44'/5757'/0'/0/0
STACKS_COIN_TYPE = 5757
STACKS_DERIVATION_PATH = "m/44'/5757'/0'/0/0"

# BIP32 constants
HARDENED_OFFSET = 0x80000000

try:
    from mnemonic import Mnemonic
    MNEMONIC_AVAILABLE = True
except ImportError:
    MNEMONIC_AVAILABLE = False

try:
    from ecdsa import SECP256k1, SigningKey
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False


def check_dependencies() -> None:
    """Check if required dependencies are installed."""
    if not MNEMONIC_AVAILABLE:
        raise ImportError(
            "mnemonic library required for seed phrase support. "
            "Install with: pip install mnemonic>=0.20"
        )
    if not ECDSA_AVAILABLE:
        raise ImportError(
            "ecdsa library required for key derivation. "
            "Install with: pip install ecdsa>=0.18.0"
        )


def validate_mnemonic(seed_phrase: str) -> bool:
    """
    Validate a BIP39 mnemonic seed phrase.

    :param seed_phrase: Space-separated seed phrase (12, 15, 18, 21, or 24 words)
    :return: True if valid
    """
    check_dependencies()

    mnemo = Mnemonic("english")
    return mnemo.check(seed_phrase.strip())


def mnemonic_to_seed(seed_phrase: str, passphrase: str = "") -> bytes:
    """
    Convert BIP39 mnemonic to seed bytes.

    :param seed_phrase: Space-separated seed phrase
    :param passphrase: Optional BIP39 passphrase
    :return: 64-byte seed
    """
    check_dependencies()

    mnemo = Mnemonic("english")
    if not mnemo.check(seed_phrase.strip()):
        raise ValueError("Invalid mnemonic seed phrase")

    return mnemo.to_seed(seed_phrase.strip(), passphrase)


def _derive_child_key(
    parent_key: bytes,
    parent_chain_code: bytes,
    index: int,
    hardened: bool = False
) -> Tuple[bytes, bytes]:
    """
    Derive a child key using BIP32.

    :param parent_key: 32-byte parent private key
    :param parent_chain_code: 32-byte parent chain code
    :param index: Child index
    :param hardened: Whether this is a hardened derivation
    :return: Tuple of (child_key, child_chain_code)
    """
    if hardened:
        index += HARDENED_OFFSET
        # Hardened: HMAC-SHA512(chain_code, 0x00 || parent_key || index)
        data = b'\x00' + parent_key + index.to_bytes(4, 'big')
    else:
        # Normal: HMAC-SHA512(chain_code, public_key || index)
        # Get compressed public key from private key
        sk = SigningKey.from_string(parent_key, curve=SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = 0x02 if y % 2 == 0 else 0x03
        public_key = bytes([prefix]) + x.to_bytes(32, 'big')
        data = public_key + index.to_bytes(4, 'big')

    h = hmac.new(parent_chain_code, data, hashlib.sha512).digest()

    # Split into key and chain code
    il = int.from_bytes(h[:32], 'big')
    child_chain_code = h[32:]

    # Add to parent key (mod n)
    parent_key_int = int.from_bytes(parent_key, 'big')
    child_key_int = (il + parent_key_int) % SECP256k1.order

    child_key = child_key_int.to_bytes(32, 'big')

    return child_key, child_chain_code


def derive_stacks_private_key(
    seed_phrase: str,
    passphrase: str = "",
    account_index: int = 0,
    address_index: int = 0,
) -> bytes:
    """
    Derive Stacks private key from seed phrase.

    Uses derivation path: m/44'/5757'/account'/0/address_index

    :param seed_phrase: BIP39 mnemonic seed phrase
    :param passphrase: Optional BIP39 passphrase
    :param account_index: Account index (default 0)
    :param address_index: Address index (default 0)
    :return: 32-byte private key
    """
    check_dependencies()

    # Convert mnemonic to seed
    seed = mnemonic_to_seed(seed_phrase, passphrase)

    # BIP32 master key derivation
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = h[:32]
    master_chain_code = h[32:]

    # Derivation path: m/44'/5757'/account'/0/address_index
    # All indices with ' are hardened
    path_indices = [
        (44, True),           # Purpose: BIP44
        (STACKS_COIN_TYPE, True),  # Coin type: Stacks (5757)
        (account_index, True),     # Account
        (0, False),           # Change: external
        (address_index, False),    # Address index
    ]

    current_key = master_key
    current_chain_code = master_chain_code

    for index, hardened in path_indices:
        current_key, current_chain_code = _derive_child_key(
            current_key,
            current_chain_code,
            index,
            hardened
        )

    return current_key


def derive_stacks_address(private_key: bytes, network: str = "mainnet") -> str:
    """
    Derive Stacks address from private key.

    :param private_key: 32-byte private key
    :param network: 'mainnet' or 'testnet'
    :return: Stacks address (e.g., SP2FY55DK4NESNH6E5CJSNZP2CQ5PZ5BX64B29FYG)
    """
    check_dependencies()

    # Get public key
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    vk = sk.get_verifying_key()

    # Compressed public key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = 0x02 if y % 2 == 0 else 0x03
    public_key = bytes([prefix]) + x.to_bytes(32, 'big')

    # Hash160 (RIPEMD160(SHA256(public_key)))
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_hash).digest()

    # Version byte
    if network == "mainnet":
        version = 22  # SP prefix
    else:
        version = 26  # ST prefix

    # Encode as c32check address
    return _encode_c32check(version, ripemd160)


def _encode_c32check(version: int, hash160: bytes) -> str:
    """
    Encode as c32check address (Stacks address format).

    :param version: Version byte (22 for mainnet, 26 for testnet)
    :param hash160: 20-byte hash
    :return: c32check encoded address
    """
    C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    # Version character mapping for Stacks addresses
    # These are specific character codes, not just c32 encoding of version
    VERSION_CHAR = {
        22: 'P',  # mainnet single-sig (SP)
        23: 'M',  # mainnet multi-sig (SM)
        26: 'T',  # testnet single-sig (ST)
        27: 'N',  # testnet multi-sig (SN)
    }

    version_char = VERSION_CHAR.get(version, 'P')

    # Checksum: first 4 bytes of SHA256(SHA256(version + hash160))
    data = bytes([version]) + hash160
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]

    # Data to encode: hash160 + checksum
    payload = hash160 + checksum

    # Convert payload to c32
    num = int.from_bytes(payload, 'big')

    # Encode in base32 (c32)
    if num == 0:
        encoded = C32_ALPHABET[0]
    else:
        encoded = ""
        while num > 0:
            encoded = C32_ALPHABET[num % 32] + encoded
            num //= 32

    # Pad with leading zeros if needed (preserve leading zero bytes)
    leading_zeros = 0
    for byte in payload:
        if byte == 0:
            leading_zeros += 1
        else:
            break

    encoded = C32_ALPHABET[0] * leading_zeros + encoded

    # Full address: 'S' + version_char + encoded_payload
    return 'S' + version_char + encoded


class StacksWallet:
    """
    Stacks wallet derived from a BIP39 seed phrase.
    """

    def __init__(
        self,
        seed_phrase: str,
        passphrase: str = "",
        network: str = "mainnet",
        account_index: int = 0,
    ):
        """
        Initialize wallet from seed phrase.

        :param seed_phrase: BIP39 mnemonic (12, 15, 18, 21, or 24 words)
        :param passphrase: Optional BIP39 passphrase
        :param network: 'mainnet' or 'testnet'
        :param account_index: Account index for derivation
        """
        check_dependencies()

        if not validate_mnemonic(seed_phrase):
            raise ValueError("Invalid seed phrase")

        self._seed_phrase = seed_phrase.strip()
        self._passphrase = passphrase
        self.network = network
        self.account_index = account_index

        # Derive private key
        self._private_key = derive_stacks_private_key(
            self._seed_phrase,
            self._passphrase,
            self.account_index,
        )

        # Derive address
        self.address = derive_stacks_address(self._private_key, self.network)

        logger.info(f"Wallet initialized: {self.address[:20]}...")

    @property
    def private_key_hex(self) -> str:
        """Get private key as hex string."""
        return self._private_key.hex()

    @property
    def private_key_bytes(self) -> bytes:
        """Get private key as bytes."""
        return self._private_key

    def get_signer(self) -> "TransactionSigner":
        """
        Get a TransactionSigner for this wallet.

        :return: TransactionSigner instance
        """
        from freqtrade.stacks.transaction import TransactionSigner
        return TransactionSigner(self.private_key_hex)

    def derive_address(self, address_index: int) -> str:
        """
        Derive a different address from same account.

        :param address_index: Address index
        :return: Derived address
        """
        key = derive_stacks_private_key(
            self._seed_phrase,
            self._passphrase,
            self.account_index,
            address_index,
        )
        return derive_stacks_address(key, self.network)


def create_wallet_from_config(config: dict) -> Optional[StacksWallet]:
    """
    Create a StacksWallet from Freqtrade config.

    Looks for seed_phrase in exchange config.

    :param config: Freqtrade configuration dict
    :return: StacksWallet or None if not configured
    """
    exchange_config = config.get("exchange", {})
    stacks_config = config.get("stacks", {})

    seed_phrase = exchange_config.get("seed_phrase", "")
    if not seed_phrase:
        return None

    passphrase = exchange_config.get("seed_passphrase", "")
    network = stacks_config.get("network", "mainnet")
    account_index = exchange_config.get("account_index", 0)

    try:
        return StacksWallet(
            seed_phrase=seed_phrase,
            passphrase=passphrase,
            network=network,
            account_index=account_index,
        )
    except Exception as e:
        logger.error(f"Failed to create wallet from config: {e}")
        return None
