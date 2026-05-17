
WEIGHTS = {
    "breach":     25,
    "entropy":    20,
    "patterns":   20,
    "dict_attack":15,
    "mutations":  10,
    "hashes":     10,   
}

ENTROPY_DEDUCTIONS = {
    "Very Weak":  20,
    "Weak":       15,
    "Reasonable":  8,
    "Strong":      3,
    "Very Strong": 0,
}

def calculate_score(results: dict) -> dict:

    score     = 100
    breakdown = {}

    if "breach" in results:
        b = results["breach"]

        if b.get("error"):
            deduction = 0
            note      = "Skipped (error or offline)"
        elif b.get("found"):
            deduction = 25  
        else:
            deduction = 0

        breakdown["breach"] = {
            "deduction": deduction,
            "max":       WEIGHTS["breach"],
            "earned":    WEIGHTS["breach"] - deduction,
        }
        score -= deduction

    if "entropy" in results:
        e         = results["entropy"]
        rating    = e.get("rating", "Very Weak")
        deduction = ENTROPY_DEDUCTIONS.get(rating, 20)

        breakdown["entropy"] = {
            "deduction": deduction,
            "max":       WEIGHTS["entropy"],
            "earned":    WEIGHTS["entropy"] - deduction,
        }
        score -= deduction

    if "patterns" in results:
        p         = results["patterns"]
        count     = p.get("issue_count", 0)

        deduction = min(WEIGHTS["patterns"], count * 5)

        breakdown["patterns"] = {
            "deduction": deduction,
            "max":       WEIGHTS["patterns"],
            "earned":    WEIGHTS["patterns"] - deduction,
        }
        score -= deduction

    if "dict_attack" in results:
        d = results["dict_attack"]

        if d.get("error"):
            deduction = 0
        elif d.get("found"):
            deduction = 15  
        else:
            deduction = 0

        breakdown["dict_attack"] = {
            "deduction": deduction,
            "max":       WEIGHTS["dict_attack"],
            "earned":    WEIGHTS["dict_attack"] - deduction,
        }
        score -= deduction

    if "mutations" in results:
        m         = results["mutations"]
        breached  = m.get("breached_mutations", 0)
        total     = m.get("total_mutations", 1)

        ratio     = breached / total if total > 0 else 0
        deduction = round(ratio * WEIGHTS["mutations"])

        breakdown["mutations"] = {
            "deduction": deduction,
            "max":       WEIGHTS["mutations"],
            "earned":    WEIGHTS["mutations"] - deduction,
        }
        score -= deduction

    if "hashes" in results:
        breakdown["hashes"] = {
            "deduction": 0,
            "max":       WEIGHTS["hashes"],
            "earned":    WEIGHTS["hashes"],
        }

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "LOW RISK"
    elif score >= 55:
        risk_level = "MEDIUM RISK"
    elif score >= 30:
        risk_level = "HIGH RISK"
    else:
        risk_level = "CRITICAL RISK"

    return {
        "score":      score,
        "risk_level": risk_level,
        "breakdown":  breakdown,
    }
