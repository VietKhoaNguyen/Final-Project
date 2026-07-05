import random
from collections import Counter
from typing import Dict, List, Optional
from datetime import date, timedelta

# ============================================================
# Basic PIN Pattern Generators
# ============================================================

# Each function below simulates one common human strategy for choosing a 6-digit PIN
def generate_random_pin(rng: random.Random) -> str: # generates a fully random 6-digit PIN
    return str(rng.randint(0, 999999)).zfill(6) # pick int in [0, 999999], pad with leading zeros to length 6

def generate_repeated_pin(rng: random.Random) -> str: # generates a PIN made of one digit repeated 6 times
    digit = str(rng.randint(0, 9)) # pick a single random digit 0-9
    return digit * 6 # repeat that digit six times to form the PIN

def generate_sequential_pin(rng: random.Random) -> str: # generates a PIN following an ascending/descending sequence
    sequences = [ # hardcoded list of common sequential 6-digit patterns
        "012345", "123456", "234567", "345678", "456789", # ascending sequences
        "987654", "876543", "765432", "654321", "543210" # descending sequences
    ]
    return rng.choice(sequences) # randomly pick one sequence from the list

def generate_birthdate_pin(rng: random.Random) -> str: # generates a PIN shaped like a birthdate (DDMMYY style)
    day = rng.randint(1, 28) # random day of month, capped at 28 to stay valid for all months
    month = rng.randint(1, 12) # random month 1-12
    year = rng.randint(0, 99) # random 2-digit year
    return f"{day:02d}{month:02d}{year:02d}" # concatenate as DD MM YY, each zero-padded to 2 digits

def generate_anniversary_pin(rng: random.Random) -> str: #  generates a PIN shaped like an anniversary date
    return generate_birthdate_pin(rng) # reuses the birthdate generator since the format is identical

def generate_year_based_pin(rng: random.Random) -> str: # generates a PIN built around a 4-digit birth year
    year = rng.randint(1950, 2005) # pick a plausible birth year
    style = rng.choice(["prefix", "suffix"]) # randomly decide whether year goes first or last
    if style == "prefix": # if year should come first
        return f"{year:04d}00" # year followed by "00" padding to reach 6 digits
    return f"00{year:04d}" # otherwise "00" padding followed by the year

def generate_significant_number_pin(rng: random.Random) -> str: # generates a PIN from culturally/personally significant numbers
    candidates = [ # hardcoded list of commonly chosen "special" number PINs
        "000000", "888888", "666666", "123123", "112233", # repeated/lucky/patterned numbers
        "121212", "520520", "131452", "999999", "101010" # more patterned/lucky numbers
    ]
    return rng.choice(candidates) # randomly select one from the list

# ============================================================
# DOB Helpers
# ============================================================

# Helper functions to simulate a user's date of birth and derive PIN guesses from it
def random_dob(rng: random.Random) -> str:
    """Generate a random realistic date of birth (age 15-70)."""
    today = date(2026, 5, 16) # fixed reference "today" date used to compute ages consistently
    min_age, max_age = 15, 70 # bounds on simulated user age in years
    start = today - timedelta(days=max_age * 365) # earliest possible birth date (oldest allowed age)
    end   = today - timedelta(days=min_age * 365) # latest possible birth date (youngest allowed age)
    delta = (end - start).days # number of days in the valid birth-date range
    dob = start + timedelta(days=rng.randint(0, delta)) # pick a random day within that range
    return dob.strftime("%Y-%m-%d") # format the date as ISO string YYYY-MM-DD

def dob_to_candidate_pins(dob: str) -> List[str]:
    """
    Convert YYYY-MM-DD into multiple 6-digit candidate PINs.
    Example: '1998-03-05' -> ['050398', '980305', '030598', ...]
    """
    year_str, month_str, day_str = dob.split("-") # split ISO date string into year/month/day parts
    yy   = year_str[-2:] # last two digits of the year
    yyyy = year_str # full 4-digit year string
    mm   = month_str # month string (already zero-padded from ISO format)
    dd   = day_str # day string (already zero-padded from ISO format)

    candidates = [ # build every plausible way a person might encode their DOB as a 6-digit PIN
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

    cleaned = [] # will hold only the candidates that are valid 6-digit numeric strings
    for pin in candidates: # iterate over every candidate string built above
        pin = str(pin) # ensure it's a string (defensive, already a string)
        if pin.isdigit() and len(pin) == 6: # keep only strings that are purely digits and exactly 6 chars long
            cleaned.append(pin) # add valid candidate to the cleaned list

    return list(dict.fromkeys(cleaned)) # remove duplicates while preserving original order

# ============================================================
# Weight Configs
# ============================================================

# Functions returning the probability weight assigned to each PIN-choice strategy
def get_default_biased_weights() -> Dict[str, float]: # returns a hand-picked default weighting of PIN strategies
    return {
        "birthdate":   0.30, # 30% of biased PINs are birthdate-shaped
        "anniversary": 0.10, # 10% are anniversary-shaped
        "repeated":    0.15, # 15% are repeated-digit PINs
        "sequential":  0.10, # 10% are sequential PINs
        "year_based":  0.10, # 10% are year-based PINs
        "significant": 0.10, # 10% are culturally significant number PINs
        "random":      0.15, # 15% are fully random PINs
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
        "birthdate":   0.26, # share of PINs that are birthdate-shaped, per survey
        "anniversary": 0.11, # share that are anniversary-shaped, per survey
        "year_based":  0.10, # share that are year-based, per survey
        "repeated":    0.15, # share that are repeated-digit PINs, per survey
        "sequential":  0.11, # share that are sequential PINs, per survey
        "significant": 0.12, # share that are culturally significant numbers, per survey
        "random":      0.15, # share that are fully random, per survey
    }

# ============================================================
# Dataset Builders
# ============================================================

# Functions that generate full synthetic PIN datasets under different attacker/user models
def generate_uniform_dataset(
    n: int = 100000, # number of PINs to generate
    seed: Optional[int] = None # optional RNG seed for reproducibility
) -> List[str]:
    rng = random.Random(seed) # create a seeded random number generator instance
    return [generate_random_pin(rng) for _ in range(n)] # generate n fully-random PINs (uniform distribution baseline)


def _generate_single_biased_pin(
    rng: random.Random, # shared random number generator instance
    weights: Dict[str, float] # mapping of strategy name -> probability weight
) -> str:
    """Generate one PIN from the biased model."""
    pattern_names   = list(weights.keys()) # extract the list of strategy names
    pattern_weights = list(weights.values()) # extract the corresponding probability weights
    pattern = rng.choices(pattern_names, weights=pattern_weights, k=1)[0] # randomly pick one strategy according to weights

    if pattern == "birthdate": # if the chosen strategy is "birthdate"
        return generate_birthdate_pin(rng) # generate a birthdate-shaped PIN
    elif pattern == "anniversary": # if the chosen strategy is "anniversary"
        return generate_anniversary_pin(rng) # generate an anniversary-shaped PIN
    elif pattern == "repeated": # if the chosen strategy is "repeated"
        return generate_repeated_pin(rng) # generate a repeated-digit PIN
    elif pattern == "sequential": # if the chosen strategy is "sequential"
        return generate_sequential_pin(rng) # generate a sequential PIN
    elif pattern == "year_based": # if the chosen strategy is "year_based"
        return generate_year_based_pin(rng) # generate a year-based PIN
    elif pattern == "significant": # if the chosen strategy is "significant"
        return generate_significant_number_pin(rng) # generate a culturally significant number PIN
    else: # fallback case, covers the "random" strategy
        return generate_random_pin(rng) # generate a fully-random PIN

def generate_biased_dataset(
    n: int = 100000, # number of PINs to generate
    seed: Optional[int] = None, # optional RNG seed for reproducibility
    weights: Optional[Dict[str, float]] = None # optional custom strategy weights
) -> List[str]:
    rng = random.Random(seed) # create a seeded random number generator instance
    if weights is None: # if no custom weights were supplied
        weights = get_default_biased_weights() # fall back to the default hardcoded weights
    return [_generate_single_biased_pin(rng, weights) for _ in range(n)] # generate n PINs using the biased strategy mix

def generate_leakage_dataset(
    n: int = 100000, # number of PINs to generate
    dob: str = "1998-03-05", # default DOB used only when randomize_dob=False
    leak_fraction: float = 0.30, # probability a user's PIN is derived from their own DOB
    seed: Optional[int] = None, # optional RNG seed for reproducibility
    base_weights: Optional[Dict[str, float]] = None, # weights used for the non-leaked portion of PINs
    randomize_dob: bool = True, # whether each simulated user gets their own random DOB
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
    rng = random.Random(seed) # create a seeded random number generator instance
    if base_weights is None: # if no custom base weights were supplied
        base_weights = get_default_biased_weights() # fall back to the default hardcoded weights

    dataset = [] # accumulator list for the generated PINs

    for _ in range(n): # loop once per simulated user/PIN
        # Each user has their own DOB
        if randomize_dob: # if each user should get an independently random DOB
            user_dob = random_dob(rng) # generate a fresh random DOB for this user
        else:
            user_dob = dob # reuse the fixed DOB passed into the function

        use_leak = rng.random() < leak_fraction # decide whether this user's PIN is "leaked" (DOB-based) with given probability

        if use_leak: # if this user's PIN should be derived from their DOB
            candidates = dob_to_candidate_pins(user_dob) # compute all DOB-derived PIN candidates
            if candidates: # if at least one valid candidate exists
                pin = rng.choice(candidates) # randomly pick one DOB-derived candidate as the PIN
            else: # if no valid DOB-derived candidate could be built
                pin = _generate_single_biased_pin(rng, base_weights) # fall back to the biased strategy generator
        else: # if this user's PIN is not DOB-leaked
            pin = _generate_single_biased_pin(rng, base_weights) # generate PIN using the biased strategy generator

        dataset.append(pin) # add the generated PIN to the dataset

    return dataset # return the full list of generated PINs

# ============================================================
# Distribution Utilities
# ============================================================

# Helper functions to convert a raw list of PINs into a probability distribution
def dataset_to_distribution(dataset: List[str]) -> Dict[str, float]: # converts a list of PINs into a frequency distribution
    counts = Counter(dataset) # count occurrences of each unique PIN
    total  = len(dataset) # total number of PINs in the dataset
    return {pin: count / total for pin, count in counts.items()} # normalize counts into probabilities


def distribution_to_ranked_list(
    distribution: Dict[str, float] # mapping of PIN -> probability
) -> List[tuple]:
    return sorted(distribution.items(), key=lambda x: x[1], reverse=True) # sort PINs by probability, highest first

# ============================================================
# Main Entry Wrapper
# ============================================================

# Single public function that dispatches to the correct dataset generator based on model name
def generate_dataset(
    n: int = 100000, # number of PINs to generate
    model: str = "biased", # which generation model to use: "uniform", "biased", or "leakage"
    seed: Optional[int] = None, # optional RNG seed for reproducibility
    dob: str = "1998-03-05",  # DOB used by the leakage model when randomize_dob=False
    weights: Optional[Dict[str, float]] = None, # optional custom strategy weights
    use_survey_weights: bool = False, # whether to use survey-derived weights instead of defaults
    randomize_dob: bool = True, # whether the leakage model randomizes DOB per simulated user
) -> List[str]:
    model = model.lower() # normalize model name to lowercase for case-insensitive comparison

    if model == "uniform": # if uniform model requested
        return generate_uniform_dataset(n=n, seed=seed) # delegate to the uniform dataset generator

    if model == "biased": # if biased model requested
        if use_survey_weights and weights is None: # if survey weights requested and no explicit weights given
            weights = get_survey_based_weights() # use survey-derived weights
        return generate_biased_dataset(n=n, seed=seed, weights=weights) # delegate to the biased dataset generator

    if model == "leakage": # if leakage model requested
        if use_survey_weights and weights is None: # if survey weights requested and no explicit weights given
            weights = get_survey_based_weights() # use survey-derived weights
        return generate_leakage_dataset( # delegate to the leakage dataset generator
            n=n, # number of PINs to generate
            dob=dob, # fixed DOB fallback
            seed=seed, # RNG seed
            base_weights=weights, # weights for non-leaked portion
            randomize_dob=randomize_dob, # whether to randomize DOB per user
        )

    raise ValueError(f"Unsupported model type: {model}") # reject any unrecognized model name
