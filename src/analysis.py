import pandas as pd

def compute_frequency(file_path):
    df = pd.read_csv(file_path)

    freq = df['pin'].value_counts().reset_index()
    freq.columns = ['pin', 'count']

    freq['probability'] = freq['count'] / len(df)

    return freq