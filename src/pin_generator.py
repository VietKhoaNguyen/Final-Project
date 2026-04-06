import random
from collections import Counter
from typing import Dict, List, Optional

# Basic PIN Pattern Generators
def generate_random_pin(rng: random.Random) -> str:
    """Generate a completely random 6-digit PIN."""
    return str(rng.randint(0, 999999)).zfill(6)

def generate_repeated_pin(rng: random.Random) -> str:
    """Generate a repeated-digit PIN such as 111111 or 777777."""
    digit = str(rng.randint(0, 9))
    return digit * 6

def generate_sequential_pin(rng: random.Random) -> str:
    """Generate a common sequential PIN."""
    sequences = [
        "012345", "123456", "234567", "345678", "456789",
        "987654", "876543", "765432", "654321", "543210"
    ]
    return rng.choice(sequences)

def generate_birthdate_pin(rng: random.Random) -> str:
    """
    Generate a date-based 6-digit PIN using DDMMYY format.
    Example: 050398 for 5 March 1998.
    """
    day = rng.randint(1, 31)
    month = rng.randint(1, 12)
    year = rng.randint(0, 99)
    return f"{day:02d}{month:02d}{year:02d}"

def generate_anniversary_pin(rng: random.Random) -> str:
    """
    Generate a memorable anniversary-like date in DDMMYY format.
    Functionally similar to birthdate, but separated for modeling clarity.
    """
    return generate_birthdate_pin(rng)

def generate_year_based_pin(rng: random.Random) -> str:
    """
    Generate a PIN derived from a 4-digit year padded to 6 digits.
    Example: 001998 or 199800.
    """
    year = rng.randint(1950, 2025)
    style = rng.choice(["prefix", "suffix"])
    if style == "prefix":
        return f"{year:04d}00"
    return f"00{year:04d}"

def generate_significant_number_pin(rng: random.Random) -> str:
    """
    Generate culturally or personally significant simple numbers.
    """
    candidates = [
        "000000", "888888", "666666", "123123", "112233",
        "121212", "520520", "131452", "999999", "101010"
    ]
    return rng.choice(candidates)

# Leakage / Personal-info Helpers
def dob_to_candidate_pins(dob: str) -> List[str]:
    """
    Convert a DOB string in YYYY-MM-DD format into multiple 6-digit candidates.

    Example:
        dob = '1998-03-05'
        -> ['050398', '980305', '030598', '199800', '001998', ...]

    Returns unique candidates only.
    """
    year_str, month_str, day_str = dob.split("-")
    yy = year_str[-2:]
    yyyy = year_str
    mm = month_str
    dd = day_str

    candidates = [
        f"{dd}{mm}{yy}",     # DDMMYY
        f"{yy}{mm}{dd}",     # YYMMDD
        f"{mm}{dd}{yy}",     # MMDDYY
        f"{yyyy}00",         # YYYY00
        f"00{yyyy}",         # 00YYYY
        f"{dd}{dd}{yy}",     # DDDDYY
        f"{mm}{mm}{yy}",     # MMMMYY
        f"{yy}{dd}{mm}",     # YYDDMM
        f"{mm}{yy}{dd}",     # MMYYDD
    ]

    # Keep only valid 6-digit strings
    cleaned = []
    for pin in candidates:
        if len(pin) == 6 and pin.isdigit():
            cleaned.append(pin)

    # Remove duplicates while preserving order
    unique_candidates = list(dict.fromkeys(cleaned))
    return unique_candidates

# DATASET Builders
def generate_uniform_dataset(n: int = 100000, seed: Optional[int] = None) -> List[str]:
    """
    Generate a dataset where each sample is a uniformly random 6-digit PIN.
    """
    rng = random.Random(seed)
    return [generate_random_pin(rng) for _ in range(n)]

def generate_biased_dataset(
    n: int = 100000,
    seed: Optional[int] = None,
    weights: Optional[Dict[str, float]] = None
) -> List[str]:
    """
    Generate a human-biased PIN dataset using weighted pattern selection.

    Default weights reflect common memorable structures:
    - birthdate
    - anniversary
    - repeated
    - sequential
    - year_based
    - significant
    - random
    """
    rng = random.Random(seed)

    if weights is None:
        weights = {
            "birthdate": 0.30,
            "anniversary": 0.10,
            "repeated": 0.15,
            "sequential": 0.10,
            "year_based": 0.10,
            "significant": 0.10,
            "random": 0.15,
        }

    pattern_names = list(weights.keys())
    pattern_weights = list(weights.values())

    dataset = []

    for _ in range(n):
        pattern = rng.choices(pattern_names, weights=pattern_weights, k=1)[0]

        if pattern == "birthdate":
            pin = generate_birthdate_pin(rng)
        elif pattern == "anniversary":
            pin = generate_anniversary_pin(rng)
        elif pattern == "repeated":
            pin = generate_repeated_pin(rng)
        elif pattern == "sequential":
            pin = generate_sequential_pin(rng)
        elif pattern == "year_based":
            pin = generate_year_based_pin(rng)
        elif pattern == "significant":
            pin = generate_significant_number_pin(rng)
        elif pattern == "random":
            pin = generate_random_pin(rng)
        else:
            pin = generate_random_pin(rng)

        dataset.append(pin)

    return dataset

def generate_leakage_dataset(
    n: int = 100000,
    dob: str = "1998-03-05",
    leak_boost: float = 0.30,
    seed: Optional[int] = None,
    base_weights: Optional[Dict[str, float]] = None
) -> List[str]:
    """
    Generate a leakage-assisted dataset.

    Idea:
    - Start from the biased model
    - Inject DOB-derived candidates with additional probability mass

    Parameters:
    - dob: known date of birth in YYYY-MM-DD format
    - leak_boost: probability of forcing a DOB-derived PIN
    """
    rng = random.Random(seed)
    dob_candidates = dob_to_candidate_pins(dob)

    if base_weights is None:
        base_weights = {
            "birthdate": 0.25,
            "anniversary": 0.10,
            "repeated": 0.12,
            "sequential": 0.08,
            "year_based": 0.10,
            "significant": 0.10,
            "random": 0.25,
        }

    dataset = []

    for _ in range(n):
        use_leak = rng.random() < leak_boost

        if use_leak and dob_candidates:
            pin = rng.choice(dob_candidates)
        else:
            pin = generate_biased_dataset(
                n=1,
                seed=rng.randint(0, 10**9),
                weights=base_weights
            )[0]

        dataset.append(pin)

    return dataset

# Distribution Utilities
def dataset_to_distribution(dataset: List[str]) -> Dict[str, float]:
    """
    Convert a list of PIN samples into a probability distribution.
    Returns: {pin: probability}
    """
    counts = Counter(dataset)
    total = len(dataset)
    return {pin: count / total for pin, count in counts.items()}


def distribution_to_ranked_list(distribution: Dict[str, float]) -> List[tuple]:
    """
    Convert a distribution dict into a list sorted by descending probability.
    Returns: [(pin, prob), ...]
    """
    return sorted(distribution.items(), key=lambda x: x[1], reverse=True)

# MAIN Entry Wrapper
def generate_dataset(
    n: int = 100000,
    model: str = "biased",
    seed: Optional[int] = None,
    dob: str = "1998-03-05",
    weights: Optional[Dict[str, float]] = None
) -> List[str]:
    """
    Unified dataset generator.

    model:
    - 'uniform'
    - 'biased'
    - 'leakage'
    """
    model = model.lower()

    if model == "uniform":
        return generate_uniform_dataset(n=n, seed=seed)

    if model == "biased":
        return generate_biased_dataset(n=n, seed=seed, weights=weights)

    if model == "leakage":
        return generate_leakage_dataset(
            n=n,
            dob=dob,
            seed=seed,
            base_weights=weights
        )
    raise ValueError(f"Unsupported model type: {model}")