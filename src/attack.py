import random
from typing import Dict, List, Optional

import pandas as pd


def _normalize_pin(pin: str) -> str:
    return str(pin).zfill(6)


def _get_distribution_dict(freq_df: pd.DataFrame) -> Dict[str, float]:
    """Build a pin->probability dict from a train-set frequency table."""
    dist = {}
    for _, row in freq_df.iterrows():
        pin  = _normalize_pin(row["pin"])
        prob = float(row["probability"])
        dist[pin] = prob
    return dist


def _top_k_success_from_guess_order(
    guess_order: List[str],
    test_distribution: Dict[str, float],
    k: int
) -> float:
    """
    Evaluate Top-k success rate against the TEST distribution.

    The attacker uses `guess_order` (derived from the training set) and
    succeeds if the target's PIN appears within the first k guesses.
    Success probability is the cumulative probability mass of those k PINs
    in the TEST distribution.
    """
    top_guesses = guess_order[:k]
    return sum(
        test_distribution.get(_normalize_pin(pin), 0.0)
        for pin in top_guesses
    )


# ============================================================
# Guess Order Builders  (use TRAIN frequency)
# ============================================================

def build_random_guess_order(
    train_distribution: Dict[str, float],
    seed: Optional[int] = None
) -> List[str]:
    rng  = random.Random(seed)
    pins = list(train_distribution.keys())
    rng.shuffle(pins)
    return pins


def build_frequency_ranked_guess_order(train_freq_df: pd.DataFrame) -> List[str]:
    sorted_df = train_freq_df.sort_values(by="probability", ascending=False)
    return [_normalize_pin(pin) for pin in sorted_df["pin"].tolist()]


def build_rule_based_guess_order(train_freq_df: pd.DataFrame) -> List[str]:
    train_distribution = _get_distribution_dict(train_freq_df)
    all_pins = list(train_distribution.keys())

    sequential_set = {
        "012345", "123456", "234567", "345678", "456789",
        "987654", "876543", "765432", "654321", "543210"
    }
    significant_set = {
        "000000", "111111", "222222", "333333", "444444",
        "555555", "666666", "777777", "888888", "999999",
        "121212", "123123", "112233", "101010", "520520", "131452"
    }

    repeated, sequential, significant, date_like, others = [], [], [], [], []

    for pin in all_pins:
        pin = _normalize_pin(pin)
        if len(set(pin)) == 1:
            repeated.append(pin)
        elif pin in sequential_set:
            sequential.append(pin)
        elif pin in significant_set:
            significant.append(pin)
        elif _is_date_like(pin):
            date_like.append(pin)
        else:
            others.append(pin)

    for group in [repeated, sequential, significant, date_like, others]:
        group.sort(key=lambda p: train_distribution.get(p, 0.0), reverse=True)

    ordered = repeated + sequential + significant + date_like + others
    return list(dict.fromkeys(ordered))


def _is_date_like(pin: str) -> bool:
    pin = _normalize_pin(pin)
    a = int(pin[:2])
    b = int(pin[2:4])
    ddmm_like = 1 <= a <= 31 and 1 <= b <= 12
    mmdd_like = 1 <= a <= 12 and 1 <= b <= 31
    return ddmm_like or mmdd_like


def build_leakage_guess_order(
    train_freq_df: pd.DataFrame,
    leaked_candidates: List[str]
) -> List[str]:
    """
    Leakage-assisted guess order for a SINGLE target.

    The attacker knows the target's DOB and prioritizes DOB-derived
    candidates (sorted by their probability in the training distribution).
    After exhausting those, the attack falls back to frequency-ranked guessing.
    """
    train_distribution = _get_distribution_dict(train_freq_df)
    leaked_candidates  = [_normalize_pin(p) for p in leaked_candidates]

    leaked_present = [p for p in leaked_candidates if p in train_distribution]
    leaked_present.sort(key=lambda p: train_distribution[p], reverse=True)

    ranked_all = build_frequency_ranked_guess_order(train_freq_df)
    remaining  = [p for p in ranked_all if p not in set(leaked_present)]

    return leaked_present + remaining


# ============================================================
# Success Rate Evaluators  (evaluate against TEST distribution)
# ============================================================

def random_attack_success(
    train_freq_df: pd.DataFrame,
    test_distribution: Dict[str, float],
    k_values: List[int] = [1, 3, 5, 10],
    seed: Optional[int] = None
) -> Dict[str, float]:
    train_distribution = _get_distribution_dict(train_freq_df)
    guess_order = build_random_guess_order(train_distribution, seed=seed)
    return {
        f"Top-{k}": _top_k_success_from_guess_order(guess_order, test_distribution, k)
        for k in k_values
    }


def frequency_ranked_attack_success(
    train_freq_df: pd.DataFrame,
    test_distribution: Dict[str, float],
    k_values: List[int] = [1, 3, 5, 10]
) -> Dict[str, float]:
    guess_order = build_frequency_ranked_guess_order(train_freq_df)
    return {
        f"Top-{k}": _top_k_success_from_guess_order(guess_order, test_distribution, k)
        for k in k_values
    }


def rule_based_attack_success(
    train_freq_df: pd.DataFrame,
    test_distribution: Dict[str, float],
    k_values: List[int] = [1, 3, 5, 10]
) -> Dict[str, float]:
    guess_order = build_rule_based_guess_order(train_freq_df)
    return {
        f"Top-{k}": _top_k_success_from_guess_order(guess_order, test_distribution, k)
        for k in k_values
    }


def leakage_assisted_attack_success(
    train_freq_df: pd.DataFrame,
    test_distribution: Dict[str, float],
    leaked_candidates: List[str],
    k_values: List[int] = [1, 3, 5, 10]
) -> Dict[str, float]:
    guess_order = build_leakage_guess_order(train_freq_df, leaked_candidates)
    return {
        f"Top-{k}": _top_k_success_from_guess_order(guess_order, test_distribution, k)
        for k in k_values
    }


# ============================================================
# Public API
# ============================================================

def evaluate_all_attacks(
    train_freq_df: pd.DataFrame,
    test_distribution: Dict[str, float],
    leaked_candidates: Optional[List[str]] = None,
    k_values: List[int] = [1, 3, 5, 10],
    seed: Optional[int] = 42
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
    return {
        "Random": random_attack_success(
            train_freq_df, test_distribution, k_values=k_values, seed=seed
        ),
        "Frequency-Ranked": frequency_ranked_attack_success(
            train_freq_df, test_distribution, k_values=k_values
        ),
        "Rule-Based": rule_based_attack_success(
            train_freq_df, test_distribution, k_values=k_values
        ),
        "Leakage-Assisted": leakage_assisted_attack_success(
            train_freq_df, test_distribution,
            leaked_candidates=leaked_candidates or [],
            k_values=k_values
        ),
    }


def print_attack_results(results: dict) -> None:
    print("\nAttack Results:")
    if results and isinstance(next(iter(results.values())), dict):
        for attack_name, metrics in results.items():
            print(f"\n  [{attack_name}]")
            for metric_name, value in metrics.items():
                print(f"    {metric_name}: {value:.4f}")
        return
    for metric_name, value in results.items():
        print(f"  {metric_name}: {value:.4f}")
