import streamlit as st
from dashboard.components import as_mapping
def render(client,guard):
    st.title("System Health"); health=guard(client.health); ready=guard(client.readiness)
    health, ready = as_mapping(health), as_mapping(ready)
    if health.get("service") and health.get("status"): st.success(f"{health['service']}: {health['status']}")
    if ready.get("status"): st.metric("Readiness",ready["status"]); st.json(as_mapping(ready.get("checks")))
    models=guard(client.models)
    models=as_mapping(models)
    if models: st.write(f"Models ready: {models.get('ready_count',0)} · unavailable: {models.get('unavailable_count',0)}")
