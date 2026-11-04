import streamlit as st
from dashboard.components import api, guard

st.set_page_config(page_title="Network Intrusion Intelligence", page_icon="🛡️", layout="wide")
css=__import__("pathlib").Path(__file__).parent / "assets/styles.css"
st.markdown(f"<style>{css.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)
st.sidebar.title("🛡️ Network Intrusion")
st.sidebar.caption("Security Analytics & Threat Detection")
pages={"Overview":"01_Overview","Traffic Analysis":"02_Traffic_Analysis","Attack Analysis":"03_Attack_Analysis","Detection Alerts":"04_Detection_Alerts","Anomaly Analysis":"05_Anomaly_Analysis","Model Performance":"06_Model_Performance","Explainability":"07_Explainability","Dataset Management":"08_Dataset_Management","System Health":"09_System_Health"}
choice=st.sidebar.radio("Navigate", list(pages))
if st.sidebar.button("Refresh data"):
    st.cache_data.clear(); st.rerun()
st.sidebar.caption("Persisted offline analysis · refresh to fetch current backend data")
module=__import__(f"dashboard.pages.{pages[choice]}", fromlist=["render"])
module.render(api(), guard)
