import random
from collections import Counter
from typing import Dict, List, Optional
from datetime import date, timedelta

# ============================================================
# Basic PIN Pattern Generators
# ============================================================

def generate_random_pin(rng: random.Random) -> str:
    return str(rng.randint(0, 999999)).zfill(6)

def generate_repeated_pin(rng: random.Random) -> str:
    digit = str(rng.randint(0, 9))
    return digit * 6

def generate_sequential_pin(rng: random.Random) -> str:
    sequences = [
        "012345", "123456", "234567", "345678", "456789",
        "987654", "876543", "765432", "654321", "543210"
    ]
    return rng.choice(sequences)

def generate_birthdate_pin(rng: random.Random) -> str:
    day = rng.randint(1, 28)
    month = rng.randint(1, 12)
    year = rng.randint(0, 99)
    return f"{day:02d}{month:02d}{year:02d}"

def generate_anniversary_pin(rng: random.Random) -> str:
    return generate_birthdate_pin(rng)

def generate_year_based_pin(rng: random.Random) -> str:
    year = rng.randint(1950, 2005)
    style = rng.choice(["prefix", "suffix"])
    if style == "prefix":
        return f"{year:04d}00"
    return f"00{year:04d}"

def generate_significant_number_pin(rng: random.Random) -> str:
    candidates = [
        "000000", "888888", "666666", "123123", "112233",
        "121212", "520520", "131452", "999999", "101010"
    ]
    return rng.choice(candidates)

# ============================================================
# DOB Helpers
# ============================================================

def random_dob(rng: random.Random) -> str:
    """Generate a random realistic date of birth (age 15-70)."""
    today = date(2026, 5, 16)
    min_age, max_age = 15, 70
    start = today - timedelta(days=max_age * 365)
    end   = today - timedelta(days=min_age * 365)
    delta = (end - start).days
    dob = start + timedelta(days=rng.randint(0, delta))
    return dob.strftime("%Y-%m-%d")

def dob_to_candidate_pins(dob: str) -> List[str]:
    """
    Convert YYYY-MM-DD into multiple 6-digit candidate PINs.
    Example: '1998-03-05' -> ['050398', '980305', '030598', ...]
    """
    year_str, month_str, day_str = dob.split("-")
    yy   = year_str[-2:]
    yyyy = year_str
    mm   = month_str
    dd   = day_str

    candidates = [
        f"{dd}{mm}{yy}",   # DDMMYY
        f"{yy}{mm}{dd}",   # YYMMDD
        f"{mm}{dd}{yy}",   # MMDDYY
        f"{yyyy}00",       # YYYY00
        f"00{yyyy}",       # 00YYYY
        f"{dd}{yy}{mm}",   # DDYYMM
        f"{mm}{yy}{dd}",   # MMYYDD
        f"{yy}{dd}{mm}",   # YYDDMM
        f"{dd}{mm}{mm}",   # DDMMMM
        f"{mm}{dd}{dd}",   # MMDDDD
    ]

    cleaned = []
    for pin in candidates:
        pin = str(pin)
        if pin.isdigit() and len(pin) == 6:
            cleaned.append(pin)

    return list(dict.fromkeys(cleaned))

# ============================================================
# Weight Configs
# ============================================================

def get_default_biased_weights() -> Dict[str, float]:
    return {
        "birthdate":   0.30,
        "anniversary": 0.10,
        "repeated":    0.15,
        "sequential":  0.10,
        "year_based":  0.10,
        "significant": 0.10,
        "random":      0.15,
    }

def get_survey_based_weights() -> Dict[str, float]:
    """
    Weights manually derived by inspecting the anonymous survey responses
    collected in survey/Survey_result.csv (142 responses).

    The survey asked participants which strategy they use when choosing a 6-digit PIN.
    The observed distribution was:
        - date-related (birthday + anniversary combined) ≈ 47%  (31.9% birthday + 14.9% anniversary)
        - repeated digits                                ≈ 15%  (14.9%)
        - sequential digits                              ≈ 11%  (11.3%)
        - random / no pattern                            ≈ 14%  (14.1%)
        - cultural or personally significant numbers     ≈ 12%  (12.1%)

    The date-related 47% is split across three sub-categories:
        birthdate (26%), anniversary (11%), year_based (10%).

    Note: these weights are hardcoded constants derived from manual inspection
    of the survey results. The CSV file is not read at runtime.
    """
    return {
        "birthdate":   0.26,
        "anniversary": 0.11,
        "year_based":  0.10,
        "repeated":    0.15,
        "sequential":  0.11,
        "significant": 0.12,
        "random":      0.15,
    }

# ============================================================
# Dataset Builders
# ============================================================

def generate_uniform_dataset(
    n: int = 100000,
    seed: Optional[int] = None
) -> List[str]:
    rng = random.Random(seed)
    return [generate_random_pin(rng) for _ in range(n)]


def _generate_single_biased_pin(
    rng: random.Random,
    weights: Dict[str, float]
) -> str:
    """Generate one PIN from the biased model."""
    pattern_names   = list(weights.keys())
    pattern_weights = list(weights.values())
    pattern = rng.choices(pattern_names, weights=pattern_weights, k=1)[0]

    if pattern == "birthdate":
        return generate_birthdate_pin(rng)
    elif pattern == "anniversary":
        return generate_anniversary_pin(rng)
    elif pattern == "repeated":
        return generate_repeated_pin(rng)
    elif pattern == "sequential":
        return generate_sequential_pin(rng)
    elif pattern == "year_based":
        return generate_year_based_pin(rng)
    elif pattern == "significant":
        return generate_significant_number_pin(rng)
    else:
        return generate_random_pin(rng)


def generate_biased_dataset(
    n: int = 100000,
    seed: Optional[int] = None,
    weights: Optional[Dict[str, float]] = None
) -> List[str]:
    rng = random.Random(seed)
    if weights is None:
        weights = get_default_biased_weights()
    return [_generate_single_biased_pin(rng, weights) for _ in range(n)]


def generate_leakage_dataset(
    n: int = 100000,
    dob: str = "1998-03-05",
    leak_fraction: float = 0.30,
    seed: Optional[int] = None,
    base_weights: Optional[Dict[str, float]] = None,
    randomize_dob: bool = True,
) -> List[str]:
    """
    Realistic leakage model: each simulated user has their own random DOB.

    For each generated PIN:
    - A random DOB is assigned to the simulated user.
    - With probability `leak_fraction`, the user's PIN is drawn from their
      own DOB-candidate list (simulating the tendency to use personal dates).
    - Otherwise the PIN is drawn from the biased distribution.

    The `dob` parameter is kept for backward compatibility and used only when
    `randomize_dob=False` (e.g., for a single-target demo in app.py).

    The attacker model (leakage-assisted attack) knows the target's DOB and
    prioritizes that user's DOB-derived candidates — evaluated separately in
    attack.py against the test-set distribution.
    """
    rng = random.Random(seed)
    if base_weights is None:
        base_weights = get_default_biased_weights()

    dataset = []

    for _ in range(n):
        # Each user has their own DOB
        if randomize_dob:
            user_dob = random_dob(rng)
        else:
            user_dob = dob

        use_leak = rng.random() < leak_fraction

        if use_leak:
            candidates = dob_to_candidate_pins(user_dob)
            if candidates:
                pin = rng.choice(candidates)
            else:
                pin = _generate_single_biased_pin(rng, base_weights)
        else:
            pin = _generate_single_biased_pin(rng, base_weights)

        dataset.append(pin)

    return dataset


# ============================================================
# Distribution Utilities
# ============================================================

def dataset_to_distribution(dataset: List[str]) -> Dict[str, float]:
    counts = Counter(dataset)
    total  = len(dataset)
    return {pin: count / total for pin, count in counts.items()}


def distribution_to_ranked_list(
    distribution: Dict[str, float]
) -> List[tuple]:
    return sorted(distribution.items(), key=lambda x: x[1], reverse=True)


# ============================================================
# Main Entry Wrapper
# ============================================================

def generate_dataset(
    n: int = 100000,
    model: str = "biased",
    seed: Optional[int] = None,
    dob: str = "1998-03-05",
    weights: Optional[Dict[str, float]] = None,
    use_survey_weights: bool = False,
    randomize_dob: bool = True,
) -> List[str]:
    model = model.lower()

    if model == "uniform":
        return generate_uniform_dataset(n=n, seed=seed)

    if model == "biased":
        if use_survey_weights and weights is None:
            weights = get_survey_based_weights()
        return generate_biased_dataset(n=n, seed=seed, weights=weights)

    if model == "leakage":
        if use_survey_weights and weights is None:
            weights = get_survey_based_weights()
        return generate_leakage_dataset(
            n=n,
            dob=dob,
            seed=seed,
            base_weights=weights,
            randomize_dob=randomize_dob,
        )

    raise ValueError(f"Unsupported model type: {model}")
