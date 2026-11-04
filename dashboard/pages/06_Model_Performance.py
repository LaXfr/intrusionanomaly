import streamlit as st
from dashboard.components import as_mapping
def render(client,guard):
    st.title("Model Performance"); data=guard(client.metrics)
    if not data: st.info("Model metadata is unavailable."); return
    data=as_mapping(data); st.json(as_mapping(data.get("historical_evaluation"))); models=as_mapping(data.get("models")); st.write("Available models",models.get("available",[])); st.write("Unavailable",models.get("unavailable",{})); st.caption("Historical evaluation evidence inherits the limitations documented in Phase 11.")
