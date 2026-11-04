import streamlit as st
from dashboard.components import as_mapping, as_rows, count_value
def render(client,guard):
    st.title("Anomaly Analysis"); data=guard(lambda:client.traffic(group_by="event_status",limit=100))
    if data:
        data=as_mapping(data); st.metric("Anomalous flows",count_value(data.get("anomalous_flows")))
        rows=as_rows(data.get("grouped_items"))
        if rows: st.dataframe(rows,use_container_width=True)
        else: st.info("No anomaly group counts are available.")
    else: st.info("No anomaly summary is available.")
