import streamlit as st
import plotly.express as px
from dashboard.components import as_mapping, as_rows, count_mapping, count_value
def render(client,guard):
    st.title("Traffic Analysis"); datasets=guard(lambda:client.datasets(limit=100,offset=0)); rows=as_rows(as_mapping(datasets).get("items"))
    ids=["All datasets"]+[str(x["id"]) for x in rows if isinstance(x.get("id"),(str,int))]; selected=st.selectbox("Dataset",ids)
    params={"limit":100};
    if selected!="All datasets": params["dataset_id"]=selected
    data=guard(lambda:client.traffic(**params))
    if not data: st.info("No traffic summary is available."); return
    data=as_mapping(data)
    st.metric("Analyzed flows",count_value(data.get("total_flows"))); st.caption("Traffic is persisted analysis, not live packet capture.")
    categories=count_mapping(data.get("predicted_categories"))
    if categories: st.plotly_chart(px.bar(x=list(categories),y=list(categories.values()),labels={"x":"Predicted category","y":"Flows"}),use_container_width=True)
    else: st.info("No predicted categories are available.")
    st.json(data.get("scope",{}))
