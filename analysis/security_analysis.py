import streamlit as st
import pandas as pd
import plotly.express as px

# Function to load the dataset (cached)
@st.cache_data
def load_dataset():
    # Load the dataset
    dataset = pd.read_csv('kddcup99.csv')
    return dataset

def run_security_analysis():
    dataset = load_dataset()

    # Select options for visualization
    visualization_type = st.sidebar.selectbox("Select Visualization Type", ['Line Chart', 'Scatter Plot'])

    # Select the feature/column to analyze
    x_axis_column = st.selectbox("Choose X-axis feature", dataset.columns)
    y_axis_column = st.selectbox("Choose Y-axis feature", dataset.columns)

    # Generate Line Chart
    if visualization_type == 'Line Chart':
        st.write(f"Line Chart of {x_axis_column} vs {y_axis_column}")
        fig = px.line(dataset, x=x_axis_column, y=y_axis_column, title=f'{x_axis_column} vs {y_axis_column}')
        st.plotly_chart(fig)

    # Generate Scatter Plot
    elif visualization_type == 'Scatter Plot':
        st.write(f"Scatter Plot of {x_axis_column} vs {y_axis_column}")
        fig = px.scatter(dataset, x=x_axis_column, y=y_axis_column, title=f'{x_axis_column} vs {y_axis_column}')
        st.plotly_chart(fig)
