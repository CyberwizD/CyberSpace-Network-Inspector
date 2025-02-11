import pandas as pd

def load_dataset():
    # Load dataset (e.g., KDD Cup 99)
    dataset = pd.read_csv(r"C:\Users\WISDOM\Documents\Python Codes\StreamLit\CyberSpace Network Inspector\utils\kddcup99.csv")
    return dataset