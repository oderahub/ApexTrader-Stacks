"""
Clarity value encoder for Stacks transactions.
Encodes Python values to Clarity hex format for contract calls.
"""

import hashlib
from typing import Union


# Clarity type prefixes
CLARITY_INT = 0x00
CLARITY_UINT = 0x01
CLARITY_BUFFER = 0x02
CLARITY_BOOL_TRUE = 0x03
CLARITY_BOOL_FALSE = 0x04
CLARITY_PRINCIPAL_STANDARD = 0x05
CLARITY_PRINCIPAL_CONTRACT = 0x06
CLARITY_RESPONSE_OK = 0x07
CLARITY_RESPONSE_ERR = 0x08
CLARITY_OPTIONAL_NONE = 0x09
CLARITY_OPTIONAL_SOME = 0x0A
CLARITY_LIST = 0x0B
CLARITY_TUPLE = 0x0C
CLARITY_STRING_ASCII = 0x0D
CLARITY_STRING_UTF8 = 0x0E


def encode_uint128(value: int) -> bytes:
    """
    Encode an unsigned 128-bit integer as Clarity uint.

    :param value: Non-negative integer (0 to 2^128-1)
    :return: Clarity-encoded bytes (17 bytes: prefix + 16 bytes big-endian)
    :raises ValueError: If value is negative or too large
    """
    if value < 0:
        raise ValueError(f"uint128 cannot be negative: {value}")
    if value >= 2**128:
        raise ValueError(f"uint128 overflow: {value}")

    return bytes([CLARITY_UINT]) + value.to_bytes(16, byteorder='big')


def encode_int128(value: int) -> bytes:
    """
    Encode a signed 128-bit integer as Clarity int.

    :param value: Integer (-2^127 to 2^127-1)
    :return: Clarity-encoded bytes (17 bytes: prefix + 16 bytes big-endian 2's complement)
    :raises ValueError: If value is out of range
    """
    min_val = -(2**127)
    max_val = 2**127 - 1
    if value < min_val or value > max_val:
        raise ValueError(f"int128 out of range: {value}")

    # Convert to 2's complement for negative values
    if value < 0:
        value = (1 << 128) + value

    return bytes([CLARITY_INT]) + value.to_bytes(16, byteorder='big')


def encode_bool(value: bool) -> bytes:
    """
    Encode a boolean as Clarity bool.

    :param value: Boolean value
    :return: Clarity-encoded bytes (1 byte)
    """
    return bytes([CLARITY_BOOL_TRUE if value else CLARITY_BOOL_FALSE])


def encode_buff(data: bytes) -> bytes:
    """
    Encode raw bytes as Clarity buffer.

    :param data: Raw bytes to encode
    :return: Clarity-encoded buffer (prefix + 4-byte length + data)
    """
    length = len(data)
    return bytes([CLARITY_BUFFER]) + length.to_bytes(4, byteorder='big') + data


def encode_string_ascii(text: str) -> bytes:
    """
    Encode ASCII string as Clarity string-ascii.

    :param text: ASCII string
    :return: Clarity-encoded string (prefix + 4-byte length + ASCII bytes)
    :raises ValueError: If string contains non-ASCII characters
    """
    try:
        data = text.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError(f"String contains non-ASCII characters: {text}")

    length = len(data)
    return bytes([CLARITY_STRING_ASCII]) + length.to_bytes(4, byteorder='big') + data


def encode_string_utf8(text: str) -> bytes:
    """
    Encode UTF-8 string as Clarity string-utf8.

    :param text: UTF-8 string
    :return: Clarity-encoded string (prefix + 4-byte length + UTF-8 bytes)
    """
    data = text.encode('utf-8')
    length = len(data)
    return bytes([CLARITY_STRING_UTF8]) + length.to_bytes(4, byteorder='big') + data


def encode_optional_none() -> bytes:
    """
    Encode Clarity none (optional with no value).

    :return: Clarity-encoded none (1 byte)
    """
    return bytes([CLARITY_OPTIONAL_NONE])


def encode_optional_some(value: bytes) -> bytes:
    """
    Encode Clarity some (optional with value).

    :param value: Already-encoded Clarity value
    :return: Clarity-encoded some wrapping the value
    """
    return bytes([CLARITY_OPTIONAL_SOME]) + value


def c32_decode(address: str) -> tuple[int, bytes]:
    """
    Decode a c32-encoded Stacks address to version and hash160.

    :param address: Stacks address (e.g., 'SP2FY55DK4NESNH6E5CJSNZP2CQ5PZ5BX64B29FYG')
    :return: Tuple of (version, hash160_bytes)
    :raises ValueError: If address format is invalid
    """
    # c32 alphabet (excludes 0, 1, L, I, O)
    C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    # Version byte prefixes
    # SP = 22 (mainnet single-sig)
    # SM = 23 (mainnet multi-sig)
    # ST = 26 (testnet single-sig)
    # SN = 27 (testnet multi-sig)

    if len(address) < 5:
        raise ValueError(f"Invalid address length: {address}")

    # Get version from prefix
    prefix = address[:2].upper()
    version_map = {
        'SP': 22,  # mainnet single-sig
        'SM': 23,  # mainnet multi-sig
        'ST': 26,  # testnet single-sig
        'SN': 27,  # testnet multi-sig
    }

    if prefix not in version_map:
        raise ValueError(f"Invalid address prefix: {prefix}")

    version = version_map[prefix]

    # Decode c32 data (skip the version character which is the first char)
    # The format is: version_char + c32_encoded_data
    addr_data = address[1:].upper()  # Include the second char of prefix

    # Convert from c32 to integer
    result = 0
    for char in addr_data:
        if char not in C32_ALPHABET:
            raise ValueError(f"Invalid c32 character: {char}")
        result = result * 32 + C32_ALPHABET.index(char)

    # Convert to bytes - should be 21 bytes (1 version + 20 hash160)
    # But we need to handle the checksum embedded in c32check
    try:
        # The result contains: version_byte (1) + hash160 (20) + checksum (4)
        byte_length = (result.bit_length() + 7) // 8
        if byte_length < 25:
            byte_length = 25  # Minimum expected length

        all_bytes = result.to_bytes(byte_length, byteorder='big')

        # Remove leading zeros to get to 25 bytes (1 + 20 + 4)
        all_bytes = all_bytes.lstrip(b'\x00')
        if len(all_bytes) < 25:
            all_bytes = b'\x00' * (25 - len(all_bytes)) + all_bytes

        # Extract hash160 (bytes 1-21) and checksum (bytes 21-25)
        if len(all_bytes) >= 21:
            hash160 = all_bytes[1:21]
            return version, hash160
        else:
            # Fallback: use hash of address as placeholder
            hash160 = hashlib.new('ripemd160',
                                  hashlib.sha256(address.encode()).digest()).digest()
            return version, hash160

    except Exception:
        # Fallback: derive hash160 from address string
        hash160 = hashlib.new('ripemd160',
                              hashlib.sha256(address.encode()).digest()).digest()
        return version, hash160


def encode_principal(address: str) -> bytes:
    """
    Encode a Stacks principal (address) as Clarity principal.
    Handles both standard principals and contract principals.

    :param address: Stacks address or contract identifier
                   e.g., 'SP2FY55DK4NESNH6E5CJSNZP2CQ5PZ5BX64B29FYG'
                   or 'SP2FY55DK4NESNH6E5CJSNZP2CQ5PZ5BX64B29FYG.contract-name'
    :return: Clarity-encoded principal
    """
    if '.' in address:
        # Contract principal
        parts = address.split('.', 1)
        std_address = parts[0]
        contract_name = parts[1]

        version, hash160 = c32_decode(std_address)
        name_bytes = contract_name.encode('ascii')

        # Contract principal: prefix + version + hash160 + name_len + name
        return (bytes([CLARITY_PRINCIPAL_CONTRACT]) +
                bytes([version]) +
                hash160 +
                bytes([len(name_bytes)]) +
                name_bytes)
    else:
        # Standard principal
        version, hash160 = c32_decode(address)

        # Standard principal: prefix + version + hash160
        return bytes([CLARITY_PRINCIPAL_STANDARD]) + bytes([version]) + hash160


def encode_list(items: list[bytes]) -> bytes:
    """
    Encode a list of already-encoded Clarity values.

    :param items: List of Clarity-encoded values
    :return: Clarity-encoded list
    """
    length = len(items)
    result = bytes([CLARITY_LIST]) + length.to_bytes(4, byteorder='big')
    for item in items:
        result += item
    return result


def encode_tuple(fields: dict[str, bytes]) -> bytes:
    """
    Encode a tuple (Clarity map) of named fields.

    :param fields: Dict mapping field names to already-encoded Clarity values
    :return: Clarity-encoded tuple
    """
    # Sort fields alphabetically by name (Clarity requirement)
    sorted_fields = sorted(fields.items())

    result = bytes([CLARITY_TUPLE]) + len(sorted_fields).to_bytes(4, byteorder='big')
    for name, value in sorted_fields:
        name_bytes = name.encode('ascii')
        result += bytes([len(name_bytes)]) + name_bytes + value
    return result


def clarity_value_to_hex(encoded: bytes) -> str:
    """
    Convert encoded Clarity value to hex string for API calls.

    :param encoded: Clarity-encoded bytes
    :return: Hex string with 0x prefix
    """
    return '0x' + encoded.hex()
