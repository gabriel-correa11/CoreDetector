import pandas as pd

def process_data_types(df: pd.DataFrame) -> pd.DataFrame:
    if 'is_fraud' in df.columns:
        df['is_fraud'] = df['is_fraud'].apply(lambda x: 1 if x is True or x == 1 else 0)
    return df