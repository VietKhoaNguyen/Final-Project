import random
from typing import Dict, List, Optional

import pandas as pd

def _normalize_pin(pin: str) -> str:
    return str(pin).zfill(6)

def _get_distribution_dict(freq_df: pd.DataFrame) -> Dict[str, float]:
    dist = {}
    for _, row in freq_df.iterrows():
        pin = _normalize_pin(row["pin"])
        prob = float(row["probability"])
        dist[pin] = prob
    return dist

def _top_k_success_from_guess_order(
    guess_order: List[str],
    distribution: Dict[str, float],
    k: int
    
) -> float:
    top_guesses = guess_order[:k]
    return sum(distribution.get(_normalize_pin(pin), 0.0) for pin in top_guesses)

# RANDOM ATTACK
def build_random_guess_order(
    distribution: Dict[str, float],
    seed: Optional[int] = None
) -> List[str]:
    rng = random.Random(seed)
    pins = list(distribution.keys())
    rng.shuffle(pins)
    return pins

def random_attack_success(
    freq_df: pd.DataFrame,
    k_values: List[int] = [1, 3, 5, 10],
    seed: Optional[int] = None
    
) -> Dict[str, float]:
    distribution = _get_distribution_dict(freq_df)
    guess_order = build_random_guess_order(distribution, seed=seed)

    results = {}
    for k in k_values:
        results[f"Top-{k}"] = _top_k_success_from_guess_order(guess_order, distribution, k)
    return results

# FREQ-RANKED ATTACK
def build_frequency_ranked_guess_order(freq_df: pd.DataFrame) -> List[str]:
    sorted_df = freq_df.sort_values(by="probability", ascending=False)
    return [_normalize_pin(pin) for pin in sorted_df["pin"].tolist()]

def frequency_ranked_attack_success(
    freq_df: pd.DataFrame,
    k_values: List[int] = [1, 3, 5, 10]
    
) -> Dict[str, float]:
    distribution = _get_distribution_dict(freq_df)
    guess_order = build_frequency_ranked_guess_order(freq_df)

    results = {}
    for k in k_values:
        results[f"Top-{k}"] = _top_k_success_from_guess_order(guess_order, distribution, k)
    return results

# RULE-BASED ATTACK
def _is_date_like(pin: str) -> bool:
    pin = _normalize_pin(pin)
    a = int(pin[:2])
    b = int(pin[2:4])

    ddmm_like = 1 <= a <= 31 and 1 <= b <= 12
    mmdd_like = 1 <= a <= 12 and 1 <= b <= 31
    return ddmm_like or mmdd_like

def build_rule_based_guess_order(freq_df: pd.DataFrame) -> List[str]:
    distribution = _get_distribution_dict(freq_df)
    all_pins = list(distribution.keys())

    repeated = []
    sequential = []
    significant = []
    date_like = []
    others = []

    sequential_set = {
        "012345", "123456", "234567", "345678", "456789",
        "987654", "876543", "765432", "654321", "543210"
    }

    significant_set = {
        "000000", "111111", "222222", "333333", "444444",
        "555555", "666666", "777777", "888888", "999999",
        "121212", "123123", "112233", "101010", "520520", "131452"
    }

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

    repeated.sort(key=lambda p: distribution[p], reverse=True)
    sequential.sort(key=lambda p: distribution[p], reverse=True)
    significant.sort(key=lambda p: distribution[p], reverse=True)
    date_like.sort(key=lambda p: distribution[p], reverse=True)
    others.sort(key=lambda p: distribution[p], reverse=True)

    ordered = repeated + sequential + significant + date_like + others
    ordered = list(dict.fromkeys(ordered))
    return ordered

def rule_based_attack_success(
    freq_df: pd.DataFrame,
    k_values: List[int] = [1, 3, 5, 10]
) -> Dict[str, float]:
    distribution = _get_distribution_dict(freq_df)
    guess_order = build_rule_based_guess_order(freq_df)

    results = {}
    for k in k_values:
        results[f"Top-{k}"] = _top_k_success_from_guess_order(guess_order, distribution, k)
    return results

# LEAKAGE-ASSISTED ATTACK
def build_leakage_guess_order(
    freq_df: pd.DataFrame,
    leaked_candidates: List[str]
) -> List[str]:
    distribution = _get_distribution_dict(freq_df)
    leaked_candidates = [_normalize_pin(pin) for pin in leaked_candidates]

    leaked_present = [pin for pin in leaked_candidates if pin in distribution]
    leaked_present.sort(key=lambda p: distribution[p], reverse=True)

    ranked_all = build_frequency_ranked_guess_order(freq_df)
    remaining = [pin for pin in ranked_all if pin not in leaked_present]

    return leaked_present + remaining

def leakage_assisted_attack_success(
    freq_df: pd.DataFrame,
    leaked_candidates: List[str],
    k_values: List[int] = [1, 3, 5, 10]
    
) -> Dict[str, float]:
    distribution = _get_distribution_dict(freq_df)
    guess_order = build_leakage_guess_order(freq_df, leaked_candidates)

    results = {}
    for k in k_values:
        results[f"Top-{k}"] = _top_k_success_from_guess_order(guess_order, distribution, k)
    return results

# Public APIS
def evaluate_attack_strategy(
    freq_df: pd.DataFrame,
    strategy: str = "frequency",
    leaked_candidates: Optional[List[str]] = None,
    k_values: List[int] = [1, 3, 5, 10],
    seed: Optional[int] = 42
) -> Dict[str, float]:
    strategy = strategy.lower()

    if strategy == "random":
        return random_attack_success(freq_df, k_values=k_values, seed=seed)

    if strategy == "frequency":
        return frequency_ranked_attack_success(freq_df, k_values=k_values)

    if strategy == "rule":
        return rule_based_attack_success(freq_df, k_values=k_values)

    if strategy == "leakage":
        if leaked_candidates is None:
            leaked_candidates = []
        return leakage_assisted_attack_success(
            freq_df, leaked_candidates=leaked_candidates, k_values=k_values
        )

    raise ValueError(f"Unsupported strategy: {strategy}")

def evaluate_all_attacks(
    freq_df: pd.DataFrame,
    leaked_candidates: Optional[List[str]] = None,
    k_values: List[int] = [1, 3, 5, 10],
    seed: Optional[int] = 42
) -> Dict[str, Dict[str, float]]:
    return {
        "Random": evaluate_attack_strategy(
            freq_df, strategy="random", k_values=k_values, seed=seed
        ),
        "Frequency-Ranked": evaluate_attack_strategy(
            freq_df, strategy="frequency", k_values=k_values
        ),
        "Rule-Based": evaluate_attack_strategy(
            freq_df, strategy="rule", k_values=k_values
        ),
        "Leakage-Assisted": evaluate_attack_strategy(
            freq_df,
            strategy="leakage",
            leaked_candidates=leaked_candidates or [],
            k_values=k_values
        ),
    }

def print_attack_results(results):
    print("\nAttack Results:")

    if results and isinstance(next(iter(results.values())), dict):
        for attack_name, metrics in results.items():
            print(f"\n[{attack_name}]")
            for metric_name, value in metrics.items():
                print(f"{metric_name}: {value:.4f}")
        return

    for metric_name, value in results.items():
        print(f"{metric_name}: {value:.4f}")