import streamlit as st
from dashboard.services.export_service import csv_bytes,json_bytes
from dashboard.components import as_mapping, as_rows
def render(client,guard):
    st.title("Detection Alerts"); sev=st.selectbox("Severity",["All","CRITICAL","HIGH","MEDIUM","LOW"]); status=st.selectbox("Status",["All","NEW","ACKNOWLEDGED","INVESTIGATING","RESOLVED","DISMISSED"])
    p={"limit":50,"offset":0};
    if sev!="All":p["severity"]=sev
    if status!="All":p["status"]=status
    result=guard(lambda:client.alerts(**p)); rows=as_rows(as_mapping(result).get("items"))
    if not rows: st.info("No alerts match these filters."); return
    st.dataframe(rows,use_container_width=True,hide_index=True); st.download_button("Export filtered alerts (CSV)",csv_bytes(rows),"alerts.csv","text/csv"); st.download_button("Export alerts (JSON)",json_bytes(rows),"alerts.json","application/json")
    alert_ids=[r.get("id") for r in rows if isinstance(r.get("id"),(str,int))]
    if not alert_ids: st.info("Alert details are unavailable because the response did not include alert IDs."); return
    aid=st.selectbox("Inspect alert",alert_ids); detail=guard(lambda:client.alert(aid))
    if detail:
        st.json(detail); new=st.selectbox("Update status",["ACKNOWLEDGED","INVESTIGATING","RESOLVED","DISMISSED"])
        if st.button("Apply status"):
            updated=guard(lambda:client.update_alert(aid,{"status":new,"changed_by":"dashboard-operator"}));
            if updated: st.success("Alert status updated."); st.rerun()
