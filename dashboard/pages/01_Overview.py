import streamlit as st
import plotly.express as px
from dashboard.components import as_mapping, as_rows, count_mapping, count_value, metric_row

def render(client, guard):
    st.title("Security Overview")
    metrics=guard(client.metrics)
    traffic=guard(client.traffic)
    if not metrics or not traffic: st.info("Connect the Phase 12 API and run an analysis to populate this overview."); return
    metrics, traffic = as_mapping(metrics), as_mapping(traffic)
    op=as_mapping(metrics.get("operational"))
    severities=as_mapping(metrics.get("persisted_alerts_by_severity"))
    metric_row([("Analyzed flows",traffic.get("total_flows")),("Benign",traffic.get("benign_predictions")),("Malicious",traffic.get("malicious_predictions")),("Anomalous",traffic.get("anomalous_flows")),("Security alerts",op.get("security_alerts")),("Critical alerts",severities.get("CRITICAL"))])
    st.caption("Persisted analysis results · binary and anomaly signals can overlap.")
    col1,col2=st.columns(2)
    with col1: st.plotly_chart(px.bar(x=["Benign","Malicious","Anomalous"],y=[count_value(traffic.get("benign_predictions")),count_value(traffic.get("malicious_predictions")),count_value(traffic.get("anomalous_flows"))],labels={"x":"Signal","y":"Flows"},title="Detector signals (overlapping)"),use_container_width=True)
    with col2:
        severities=count_mapping(traffic.get("events_by_severity"))
        if severities: st.plotly_chart(px.bar(x=list(severities),y=list(severities.values()),title="Persisted events by severity"),use_container_width=True)
        else: st.info("No persisted severity counts.")
    alerts=guard(lambda:client.alerts(limit=8,offset=0,sort_by="created_at",order="desc"))
    st.subheader("Recent alerts")
    alert_rows=as_rows(as_mapping(alerts).get("items"))
    if alert_rows: st.dataframe(alert_rows,use_container_width=True,hide_index=True)
    else: st.info("No persisted alerts.")
