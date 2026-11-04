import streamlit as st
import plotly.express as px
from dashboard.components import as_mapping, count_mapping
def render(client,guard):
    st.title("Attack Analysis"); data=guard(lambda:client.traffic(group_by="attack_category",limit=100))
    categories=count_mapping(as_mapping(data).get("predicted_categories"))
    if categories: st.plotly_chart(px.bar(x=list(categories),y=list(categories.values()),labels={"x":"Predicted category","y":"Events"}),use_container_width=True)
    else: st.info("No persisted predicted attack categories are available.")
