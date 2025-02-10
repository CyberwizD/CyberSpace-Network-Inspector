import pandas as pd

def load_dataset():
    # Load dataset (e.g., KDD Cup 99)
    dataset = pd.read_csv("kddcup99.csv")
    return dataset