import streamlit as st
from dashboard.components import as_mapping, as_rows
def render(client,guard):
    st.title("Dataset Management"); file=st.file_uploader("Register a feature-contract CSV",type=["csv"])
    if file and st.button("Upload and validate"):
        result=guard(lambda:client.upload_dataset(file.name,file.getvalue()))
        if result is not None:
            result=as_mapping(result); dataset_id=result.get("id")
            if isinstance(dataset_id,(str,int)) and str(dataset_id): st.success(f"Dataset registered: {dataset_id}"); st.json(result)
            else: st.error("The backend returned no usable dataset ID in its upload response.")
    data=guard(lambda:client.datasets(limit=50,offset=0)); rows=as_rows(as_mapping(data).get("items"))
    if rows: st.dataframe(rows,use_container_width=True,hide_index=True)
    else: st.info("No datasets registered.")
    if rows:
        dataset_ids=[str(x["id"]) for x in rows if x.get("id")]
        if not dataset_ids: st.info("Registered dataset IDs are unavailable."); return
        chosen=st.selectbox("Dataset to analyze",dataset_ids); models=as_mapping(guard(client.models)); model_rows=as_rows(models.get("items")); available={m["model_type"]:m["model_id"] for m in model_rows if isinstance(m.get("model_type"),str) and isinstance(m.get("model_id"),str)}
        engines=[e for e in ("binary","multiclass","anomaly") if e in available]; selected=st.multiselect("Detectors",engines,default=engines)
        job=None
        if st.button("Queue analysis",disabled=not selected):
            job=guard(lambda:client.create_job({"dataset_id":chosen,"engines":selected,"model_ids":{e:available[e] for e in selected}}))
        if job is not None:
            job=as_mapping(job)
            job_id=as_mapping(job).get("id")
            if job_id:
                st.session_state["job_id"]=job_id; st.success(f"Job {job_id} submitted.")
            else: st.error("The backend accepted no usable job ID in its response.")
    job_id=st.session_state.get("job_id")
    if job_id and st.button("Refresh job status"):
        job=guard(lambda:client.job(job_id))
        if job is not None:
            job=as_mapping(job)
            if job: st.json(job)
            else: st.error("The backend returned an invalid analysis-job response.")
