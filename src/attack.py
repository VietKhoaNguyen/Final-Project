import random
from typing import Dict, List, Optional

import pandas as pd

def _normalize_pin(pin: str) -> str: # ensures any PIN value is represented as a 6-digit zero-padded string
    return str(pin).zfill(6) # cast to string and left-pad with zeros to length 6

def _get_distribution_dict(freq_df: pd.DataFrame) -> Dict[str, float]:
    """Build a pin->probability dict from a train-set frequency table."""
    dist = {} # accumulator dict mapping PIN -> probability
    for _, row in freq_df.iterrows(): # iterate over each row of the frequency DataFrame
        pin  = _normalize_pin(row["pin"]) # normalize the PIN value from this row
        prob = float(row["probability"]) # convert the probability column to float
        dist[pin] = prob # store the pin->probability mapping
    return dist # return the completed distribution dict

def _top_k_success_from_guess_order(
    guess_order: List[str], # ordered list of PIN guesses, most likely first
    test_distribution: Dict[str, float], # ground-truth probability distribution to evaluate against
    k: int # number of top guesses the attacker is allowed to try
) -> float:
    """
    Evaluate Top-k success rate against the TEST distribution.

    The attacker uses `guess_order` (derived from the training set) and
    succeeds if the target's PIN appears within the first k guesses.
    Success probability is the cumulative probability mass of those k PINs
    in the TEST distribution.
    """
    top_guesses = guess_order[:k] # take only the first k guesses from the ordered list
    return sum( # sum up the test-set probability mass covered by these k guesses
        test_distribution.get(_normalize_pin(pin), 0.0) # look up each guessed pin's probability in the test set (0 if absent)
        for pin in top_guesses # iterate over the top-k guessed pins
    )

# ============================================================
# Guess Order Builders  (use TRAIN frequency)
# ============================================================

# Each function below produces an ordered list of PIN guesses representing one attacker strategy
def build_random_guess_order( 
    train_distribution: Dict[str, float], # distribution built from the training set (only keys/PIN universe is used)
    seed: Optional[int] = None # optional RNG seed for reproducibility
) -> List[str]:
    rng  = random.Random(seed) # create a seeded random number generator instance
    pins = list(train_distribution.keys()) # collect all known PINs from the training distribution
    rng.shuffle(pins) # shuffle the PIN list into a random guessing order
    return pins # return the randomly ordered guess list

def build_frequency_ranked_guess_order(train_freq_df: pd.DataFrame) -> List[str]: # builds a guess order sorted by observed frequency
    sorted_df = train_freq_df.sort_values(by="probability", ascending=False) # sort rows by probability, highest first
    return [_normalize_pin(pin) for pin in sorted_df["pin"].tolist()] # extract and normalize the pin column in sorted order

def build_rule_based_guess_order(train_freq_df: pd.DataFrame) -> List[str]: # builds a guess order using human-knowledge pattern rules
    train_distribution = _get_distribution_dict(train_freq_df) # convert the frequency table into a pin->probability dict
    all_pins = list(train_distribution.keys()) # collect all known PINs

    sequential_set = { # set of known sequential-digit PINs, prioritized by the rule-based attacker
        "012345", "123456", "234567", "345678", "456789", # ascending sequences
        "987654", "876543", "765432", "654321", "543210" # descending sequences
    }
    significant_set = { # set of known culturally/personally significant PINs
        "000000", "111111", "222222", "333333", "444444", # repeated-digit PINs
        "555555", "666666", "777777", "888888", "999999",
        "121212", "123123", "112233", "101010", "520520", "131452" # other commonly chosen "special" PINs
    }

    repeated, sequential, significant, date_like, others = [], [], [], [], [] # buckets for each pattern category, in priority order

    for pin in all_pins: # classify every known PIN into one of the pattern buckets
        pin = _normalize_pin(pin) # normalize the PIN before classification
        if len(set(pin)) == 1: # if all digits in the PIN are identical
            repeated.append(pin) # classify as a repeated-digit PIN
        elif pin in sequential_set: # if the PIN matches a known sequential pattern
            sequential.append(pin) # classify as sequential
        elif pin in significant_set: # if the PIN matches a known significant-number pattern
            significant.append(pin) # classify as significant
        elif _is_date_like(pin): # if the PIN's digit structure looks like a date
            date_like.append(pin) # classify as date-like
        else:
            others.append(pin) # classify as a generic/unclassified PIN

    for group in [repeated, sequential, significant, date_like, others]: # for each pattern bucket
        group.sort(key=lambda p: train_distribution.get(p, 0.0), reverse=True) # sort within the bucket by training-set frequency, highest first

    ordered = repeated + sequential + significant + date_like + others # concatenate buckets in attacker priority order
    return list(dict.fromkeys(ordered)) # remove any duplicate PINs while preserving order

def _is_date_like(pin: str) -> bool: # heuristic check for whether a PIN's first four digits resemble a day/month date
    pin = _normalize_pin(pin) # normalize the PIN before inspection
    a = int(pin[:2]) # first two digits, interpreted as a potential day or month
    b = int(pin[2:4]) # next two digits, interpreted as a potential month or day
    ddmm_like = 1 <= a <= 31 and 1 <= b <= 12 # check if it could be DD then MM
    mmdd_like = 1 <= a <= 12 and 1 <= b <= 31 # check if it could be MM then DD
    return ddmm_like or mmdd_like # PIN is considered date-like if either interpretation is valid

def build_leakage_guess_order(
    train_freq_df: pd.DataFrame, # frequency table from the training set
    leaked_candidates: List[str] # DOB-derived candidate PINs known to the attacker for this target
) -> List[str]:
    """
    Leakage-assisted guess order for a SINGLE target.

    The attacker knows the target's DOB and prioritizes DOB-derived
    candidates (sorted by their probability in the training distribution).
    After exhausting those, the attack falls back to frequency-ranked guessing.
    """
    train_distribution = _get_distribution_dict(train_freq_df) # convert the frequency table into a pin->probability dict
    leaked_candidates  = [_normalize_pin(p) for p in leaked_candidates] # normalize every leaked candidate PIN

    leaked_present = [p for p in leaked_candidates if p in train_distribution] # keep only leaked candidates that actually appear in the training distribution
    leaked_present.sort(key=lambda p: train_distribution[p], reverse=True) # order the leaked candidates by their training-set probability, highest first

    ranked_all = build_frequency_ranked_guess_order(train_freq_df) # get the standard frequency-ranked fallback guess order
    remaining  = [p for p in ranked_all if p not in set(leaked_present)] # remove already-included leaked candidates from the fallback list

    return leaked_present + remaining # try leaked DOB candidates first, then fall back to frequency ranking

# ============================================================
# Success Rate Evaluators  (evaluate against TEST distribution)
# ============================================================

# Each function below evaluates a single attack strategy's Top-k success rates
def random_attack_success(
    train_freq_df: pd.DataFrame, # training-set frequency table
    test_distribution: Dict[str, float], # test-set probability distribution to evaluate success against
    k_values: List[int] = [1, 3, 5, 10], # which Top-k thresholds to compute
    seed: Optional[int] = None # optional RNG seed for reproducibility
) -> Dict[str, float]:
    train_distribution = _get_distribution_dict(train_freq_df) # convert the frequency table into a pin->probability dict
    guess_order = build_random_guess_order(train_distribution, seed=seed) # build a randomly shuffled guess order
    return { # compute Top-k success rate for each requested k
        f"Top-{k}": _top_k_success_from_guess_order(guess_order, test_distribution, k)
        for k in k_values
    }

def frequency_ranked_attack_success(
    train_freq_df: pd.DataFrame, # training-set frequency table
    test_distribution: Dict[str, float], # test-set probability distribution to evaluate success against
    k_values: List[int] = [1, 3, 5, 10] # which Top-k thresholds to compute
) -> Dict[str, float]:
    guess_order = build_frequency_ranked_guess_order(train_freq_df) # build a guess order sorted by training-set frequency
    return { # compute Top-k success rate for each requested k
        f"Top-{k}": _top_k_success_from_guess_order(guess_order, test_distribution, k)
        for k in k_values
    }

def rule_based_attack_success(
    train_freq_df: pd.DataFrame, # training-set frequency table
    test_distribution: Dict[str, float], # test-set probability distribution to evaluate success against
    k_values: List[int] = [1, 3, 5, 10] # which Top-k thresholds to compute
) -> Dict[str, float]:
    guess_order = build_rule_based_guess_order(train_freq_df) # build a guess order using pattern-based rules
    return { # compute Top-k success rate for each requested k
        f"Top-{k}": _top_k_success_from_guess_order(guess_order, test_distribution, k)
        for k in k_values
    }

def leakage_assisted_attack_success(
    train_freq_df: pd.DataFrame, # training-set frequency table
    test_distribution: Dict[str, float], # test-set probability distribution to evaluate success against
    leaked_candidates: List[str], # list of leaked candidate PINs
    k_values: List[int] = [1, 3, 5, 10] # which Top-k thresholds to compute
) -> Dict[str, float]:
    guess_order = build_leakage_guess_order(train_freq_df, leaked_candidates) # build a guess order prioritizing leaked DOB candidates
    return { # compute Top-k success rate for each requested k
        f"Top-{k}": _top_k_success_from_guess_order(guess_order, test_distribution, k)
        for k in k_values
    }

# ============================================================
# Public API
# ============================================================

def evaluate_all_attacks(
    train_freq_df: pd.DataFrame, # training-set frequency table
    test_distribution: Dict[str, float], # test-set probability distribution to evaluate success against
    leaked_candidates: Optional[List[str]] = None, # DOB-derived candidates for the leakage-assisted attack
    k_values: List[int] = [1, 3, 5, 10], # which Top-k thresholds to compute
    seed: Optional[int] = 42 # random seed used by the random-guess attack
) -> Dict[str, Dict[str, float]]:
    """
    Evaluate all four attack strategies using train/test split.

    Parameters
    ----------
    train_freq_df     : frequency table built from the TRAINING set
    test_distribution : probability distribution built from the TEST set
    leaked_candidates : DOB-derived candidate PINs for the target user
    k_values          : list of k values for Top-k evaluation
    seed              : random seed for the random attack
    """
    return { # run every attack strategy and collect their Top-k results into one dict
        "Random": random_attack_success( # evaluate the pure random-guessing baseline attack
            train_freq_df, test_distribution, k_values=k_values, seed=seed
        ),
        "Frequency-Ranked": frequency_ranked_attack_success( # evaluate the frequency-ranked attack
            train_freq_df, test_distribution, k_values=k_values
        ),
        "Rule-Based": rule_based_attack_success( # evaluate the pattern-rule-based attack
            train_freq_df, test_distribution, k_values=k_values
        ),
        "Leakage-Assisted": leakage_assisted_attack_success( # evaluate the DOB-leakage-assisted attack
            train_freq_df, test_distribution,
            leaked_candidates=leaked_candidates or [], # use empty list if no leaked candidates were provided
            k_values=k_values
        ),
    }

def print_attack_results(results: dict) -> None: # pretty-prints attack evaluation results to the console
    print("\nAttack Results:") # header line
    if results and isinstance(next(iter(results.values())), dict): # check whether results is nested (multiple attacks) vs flat (single attack)
        for attack_name, metrics in results.items(): # iterate over each attack's results
            print(f"\n  [{attack_name}]") # print the attack strategy name as a sub-header
            for metric_name, value in metrics.items(): # iterate over each Top-k metric for this attack
                print(f"    {metric_name}: {value:.4f}") # print the metric name and its value formatted to 4 decimals
        return # exit after printing the nested structure
    for metric_name, value in results.items(): # fallback: results is a flat dict of metrics
        print(f"  {metric_name}: {value:.4f}") # print each metric name and value formatted to 4 decimals
