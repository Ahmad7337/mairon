import math

CHARSET_LOWERCASE = 26    
CHARSET_UPPERCASE = 26    
CHARSET_DIGITS    = 10    
CHARSET_SPECIAL   = 32    

ENTROPY_RATINGS = [
    (28,  "Very Weak",  "Easily cracked in seconds"),
    (36,  "Weak",       "Crackable in minutes to hours"),
    (60,  "Reasonable", "Resistant to casual attacks"),
    (128, "Strong",     "Resistant to serious attacks"),
    (999, "Very Strong","Highly resistant to all known attacks"),
]

def calculate_entropy(password: str) -> dict:
    if not password:
        return {
            "entropy":      0.0,
            "charset_size": 0,
            "length":       0,
            "rating":       "Very Weak",
            "description":  "Empty password",
            "has_lower":    False,
            "has_upper":    False,
            "has_digit":    False,
            "has_special":  False,
        }
    has_lower   = any(c.islower() for c in password)
    has_upper   = any(c.isupper() for c in password)
    has_digit   = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    charset_size = 0
    if has_lower:   charset_size += CHARSET_LOWERCASE
    if has_upper:   charset_size += CHARSET_UPPERCASE
    if has_digit:   charset_size += CHARSET_DIGITS
    if has_special: charset_size += CHARSET_SPECIAL

    if charset_size == 0:
        charset_size = 1

    entropy = len(password) * math.log2(charset_size)
    entropy = round(entropy, 2)

    rating      = "Very Weak"
    description = "Easily cracked in seconds"
    for threshold, label, desc in ENTROPY_RATINGS:
        if entropy < threshold:
            rating      = label
            description = desc
            break

    return {
        "entropy":      entropy,
        "charset_size": charset_size,
        "length":       len(password),
        "rating":       rating,
        "description":  description,
        "has_lower":    has_lower,
        "has_upper":    has_upper,
        "has_digit":    has_digit,
        "has_special":  has_special,
    }
