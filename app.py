import os
import pandas as pd
import streamlit as st

from src.pin_generator import generate_dataset, dob_to_candidate_pins
from src.analysis import compute_security_metrics
from src.attack import evaluate_all_attacks

DATA_DIR = "data"
RESULTS_DIR = "results"

def ensure_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

def run_model(model_name: str, dob: str, n: int, seed: int, use_survey_weights: bool):
    pins = generate_dataset(
        n=n,
        model=model_name,
        seed=seed,
        dob=dob,
        use_survey_weights=use_survey_weights,
    )

    df = pd.DataFrame(pins, columns=["pin"])
    df["pin"] = df["pin"].astype(str).str.zfill(6)

    freq = df["pin"].value_counts().reset_index()
    freq.columns = ["pin", "count"]
    freq["probability"] = freq["count"] / len(df)

    metrics = compute_security_metrics(freq)

    leaked_candidates = dob_to_candidate_pins(dob)
    attacks = evaluate_all_attacks(
        freq,
        leaked_candidates=leaked_candidates,
        k_values=[1, 3, 5, 10],
        seed=seed,
    )

    return freq, metrics, attacks

def flatten_attacks(attacks: dict) -> pd.DataFrame:
    rows = []
    for attack_name, values in attacks.items():
        row = {"Attack Strategy": attack_name}
        row.update(values)
        rows.append(row)
    return pd.DataFrame(rows)

def build_summary_df(results: dict) -> pd.DataFrame:
    rows = []
    for model_name, result in results.items():
        metrics = result["metrics"]
        attacks = result["attacks"]

        row = {
            "Model": model_name,
            "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
            "Min-Entropy (bits)": metrics["Min-Entropy (bits)"],
            "Expected Guesses": metrics["Expected Guesses"],
        }

        for attack_name, attack_metrics in attacks.items():
            for metric_name, value in attack_metrics.items():
                row[f"{attack_name} - {metric_name}"] = value

        rows.append(row)

    return pd.DataFrame(rows)

def save_outputs(results: dict) -> None:
    ensure_dirs()

    summary_df = build_summary_df(results)
    summary_path = os.path.join(RESULTS_DIR, "summary_all_models.csv")
    summary_df.to_csv(summary_path, index=False)

    for model_name, result in results.items():
        freq_path = os.path.join(RESULTS_DIR, f"frequency_{model_name}.csv")
        result["freq"].to_csv(freq_path, index=False)

        dataset_path = os.path.join(DATA_DIR, f"generated_{model_name}_pins.csv")
        pd.DataFrame(result["raw_pins"], columns=["pin"]).to_csv(dataset_path, index=False)

def show_metrics_cards(results: dict, models: list[str]) -> None:
    cols = st.columns(len(models))

    for i, model_name in enumerate(models):
        with cols[i]:
            st.subheader(model_name.upper())
            st.metric(
                "Shannon Entropy",
                f"{results[model_name]['metrics']['Shannon Entropy (bits)']:.2f}",
            )
            st.metric(
                "Min-Entropy",
                f"{results[model_name]['metrics']['Min-Entropy (bits)']:.2f}",
            )
            st.metric(
                "Expected Guesses",
                f"{results[model_name]['metrics']['Expected Guesses']:.0f}",
            )

def show_top10_table(freq_df: pd.DataFrame) -> None:
    st.dataframe(freq_df.head(10), use_container_width=True)

def show_attack_table(attacks: dict) -> None:
    st.dataframe(flatten_attacks(attacks), use_container_width=True)

def show_rank_distribution(freq_df: pd.DataFrame, top_n: int = 100) -> None:
    ranked = freq_df.sort_values(by="probability", ascending=False).reset_index(drop=True)
    ranked["rank"] = ranked.index + 1
    chart_df = ranked.loc[: top_n - 1, ["rank", "probability"]].set_index("rank")
    st.line_chart(chart_df)

def main() -> None:
    st.set_page_config(
        page_title="PIN Security Analysis Demo",
        page_icon="🔐",
        layout="wide",
    )

    st.title("🔐 Low-Entropy Attacks on 6-Digit PINs")
    st.write(
        "Interactive demo for comparing uniform, biased, and leakage-based PIN models "
        "under multiple guessing attacks."
    )

    st.sidebar.header("Experiment Settings")

    n = st.sidebar.slider("Dataset size", 10000, 200000, 100000, step=10000)
    seed = st.sidebar.number_input("Random seed", value=42, step=1)
    dob = st.sidebar.text_input("DOB (YYYY-MM-DD)", "1998-03-05")
    use_survey_weights = st.sidebar.checkbox("Use survey-based weights", value=True)

    run = st.sidebar.button("Run Full Comparison", type="primary")

    models = ["uniform", "biased", "leakage"]

    tab1, tab2, tab3 = st.tabs(
        ["📊 Overview", "⚔️ Model Comparison", "🔍 Deep Dive"]
    )

    if "results_cache" not in st.session_state:
        st.session_state["results_cache"] = None

    if run:
        if len(dob.split("-")) != 3:
            st.error("DOB must follow the format YYYY-MM-DD.")
            return

        ensure_dirs()

        results = {}
        with st.spinner("Running all models..."):
            for model_name in models:
                pins = generate_dataset(
                    n=n,
                    model=model_name,
                    seed=int(seed),
                    dob=dob,
                    use_survey_weights=use_survey_weights,
                )

                df = pd.DataFrame(pins, columns=["pin"])
                df["pin"] = df["pin"].astype(str).str.zfill(6)

                freq = df["pin"].value_counts().reset_index()
                freq.columns = ["pin", "count"]
                freq["probability"] = freq["count"] / len(df)

                metrics = compute_security_metrics(freq)

                leaked_candidates = dob_to_candidate_pins(dob)
                attacks = evaluate_all_attacks(
                    freq,
                    leaked_candidates=leaked_candidates,
                    k_values=[1, 3, 5, 10],
                    seed=int(seed),
                )

                results[model_name] = {
                    "raw_pins": pins,
                    "freq": freq,
                    "metrics": metrics,
                    "attacks": attacks,
                }

        save_outputs(results)
        st.session_state["results_cache"] = results
        st.success("Experiment completed.")

    results = st.session_state["results_cache"]

    if results is None:
        st.info("Choose settings in the sidebar and click 'Run Full Comparison'.")
        return

    with tab1:
        st.header("Overview")
        show_metrics_cards(results, models)

        st.markdown("---")
        st.subheader("Key Insight")
        st.success(
            "From Uniform → Biased → Leakage, entropy decreases while attack success increases. "
            "This shows that human bias and personal-information leakage substantially weaken practical PIN security."
        )

        st.subheader("Summary Table")
        st.dataframe(build_summary_df(results), use_container_width=True)

    with tab2:
        st.header("Attack Comparison")

        chart_df = pd.DataFrame(
            {
                "Model": models,
                "Top-10 Success (Frequency-Ranked)": [
                    results[m]["attacks"]["Frequency-Ranked"]["Top-10"] for m in models
                ],
                "Top-10 Success (Leakage-Assisted)": [
                    results[m]["attacks"]["Leakage-Assisted"]["Top-10"] for m in models
                ],
            }
        ).set_index("Model")

        st.bar_chart(chart_df)

        st.warning(
            "Notice how success rates increase sharply when moving from uniform PIN selection "
            "to human-biased and leakage-assisted models."
        )

        st.subheader("Per-Model Attack Tables")
        compare_model = st.selectbox("Choose model to inspect", models, index=1, key="compare_model")
        show_attack_table(results[compare_model]["attacks"])

    with tab3:
        st.header("Deep Dive")

        model_choice = st.selectbox("Select model", models, index=1, key="deep_model")

        st.subheader(f"Top 10 PINs — {model_choice.upper()}")
        show_top10_table(results[model_choice]["freq"])

        st.subheader(f"Attack Results — {model_choice.upper()}")
        show_attack_table(results[model_choice]["attacks"])

        st.subheader(f"Rank Distribution — {model_choice.upper()}")
        show_rank_distribution(results[model_choice]["freq"], top_n=100)

        st.info("A steeper drop indicates a more concentrated and more predictable PIN distribution.")

        st.subheader("Interpretation")
        st.markdown(
            f"""
- **Selected model:** `{model_choice}`
- **Lower entropy** means higher predictability.
- **Lower min-entropy** means the most likely PIN becomes easier to guess.
- **Lower expected guesses** means weaker practical security.
- **Higher Top-k success** means attackers can crack more PINs with very few attempts.
"""
        )

    st.markdown("---")
    st.subheader("Saved Output Files")
    st.code(
        "\n".join(
            [
                os.path.join(RESULTS_DIR, "summary_all_models.csv"),
                os.path.join(RESULTS_DIR, "frequency_uniform.csv"),
                os.path.join(RESULTS_DIR, "frequency_biased.csv"),
                os.path.join(RESULTS_DIR, "frequency_leakage.csv"),
            ]
        )
    )

if __name__ == "__main__":
    main()