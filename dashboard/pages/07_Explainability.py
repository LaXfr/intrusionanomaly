import streamlit as st
from dashboard.components import as_mapping, as_rows
def render(client,guard):
    st.title("Explainability")
    st.caption("Event-level SHAP values explain a persisted detector output in that model’s output units. They are not causal explanations.")
    models=guard(client.models)
    events=guard(lambda:client.events(limit=50,offset=0))
    rows=as_rows(as_mapping(events).get("items"))
    if rows:
        ids=[str(row["id"]) for row in rows if row.get("id")]
        selected=st.selectbox("Persisted detection event",ids)
        engine=st.selectbox("Detector output",["binary","multiclass","anomaly"])
        event_detail=guard(lambda:client.event(selected))
        if event_detail: st.json(event_detail)
        if st.button("Explain event"):
            result=guard(lambda:client.event_explanation(selected,engine))
            if result:
                status=result.get("availability_status")
                if status=="available":
                    st.success(f"SHAP explanation available for {result.get('model_id')} · {result.get('output_name')}")
                    st.metric("Model output",result.get("model_output_value")); st.metric("Expected value",result.get("expected_value"))
                    st.dataframe(result.get("original_feature_contributions",[]),use_container_width=True,hide_index=True)
                    st.caption(f"Additivity check passed: {result.get('additivity_diagnostic',{}).get('passed')}")
                else: st.info(f"Explanation {status}: {result.get('reason','No explanation is available for this event.')}")
    else:
        st.info("No persisted events are available for local explanation.")
    if models:
        items=as_rows(as_mapping(models).get("items"))
        ids=[m.get("model_id") for m in items if isinstance(m.get("model_id"),str)]
        if ids: st.caption("Validated persisted models: " + ", ".join(ids))
