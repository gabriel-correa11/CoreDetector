import kagglehub
import pandas as pd
import os

def fetch_and_prepare_en_data():
    path = kagglehub.dataset_download("uciml/sms-spam-collection-dataset")
    csv_path = os.path.join(path, "spam.csv")

    df = pd.read_csv(csv_path, encoding="latin-1")
    df = df.rename(columns={"v1": "label", "v2": "message_text"})

    df["is_fraud"] = (df["label"] == "spam").astype(int)
    df_final = df[["message_text", "is_fraud"]]

    os.makedirs(os.path.join("..", "data"), exist_ok=True)
    output_path = os.path.join("..", "data", "dataset_en_real.csv")
    df_final.to_csv(output_path, index=False)

if __name__ == '__main__':
    fetch_and_prepare_en_data()