import streamlit as st
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from utils import utils_dataset

@st.cache_data
def run_security_analysis():
    # Load dataset (e.g., KDD Cup 99)
    dataset = utils_dataset.load_dataset()

    # Split dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(dataset.data, dataset.target, test_size=0.2, random_state=42)

    # Train a random forest classifier
    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)

    # Evaluate the classifier
    accuracy = clf.score(X_test, y_test)
    st.write("Security Analysis:")
    st.write(f"Accuracy: {accuracy:.2f}")
