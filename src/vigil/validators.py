"""Checksum validators for structured PII types."""


def validate_rrn(digits: str) -> bool:
    """
    Validate a Korean Resident Registration Number (주민등록번호) checksum.

    Args:
        digits: exactly 13 digit string (no separators)

    Returns:
        True if the checksum is valid, False otherwise
    """
    if not isinstance(digits, str) or len(digits) != 13 or not digits.isdigit():
        return False

    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(digits[i]) * weights[i] for i in range(12))
    check = (11 - total % 11) % 10
    return check == int(digits[12])


def validate_brn(digits: str) -> bool:
    """
    Validate a Korean Business Registration Number (사업자등록번호) checksum.

    Args:
        digits: exactly 10 digit string (no separators)

    Returns:
        True if the checksum is valid, False otherwise
    """
    if not isinstance(digits, str) or len(digits) != 10 or not digits.isdigit():
        return False

    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    total = sum(int(digits[i]) * weights[i] for i in range(9))
    total += (int(digits[8]) * 5) // 10
    check = (10 - total % 10) % 10
    return check == int(digits[9])


def luhn(digits: str) -> bool:
    """
    Validate using the Luhn algorithm (e.g., credit cards).

    Args:
        digits: digit-only string (no separators)

    Returns:
        True if valid, False otherwise (including if fewer than 13 digits)
    """
    if not isinstance(digits, str) or not digits.isdigit() or len(digits) < 13:
        return False

    # Standard Luhn: starting from second-to-last digit going left,
    # double every other digit; if > 9, subtract 9; sum all digits
    total = 0
    for i, digit_char in enumerate(reversed(digits)):
        digit = int(digit_char)
        if i % 2 == 1:  # Every other digit from the right (second-to-last, fourth-to-last, ...)
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0
