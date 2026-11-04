from collections.abc import Mapping

from dashboard.api_client import ApiClient, ApiError

def api():
    import streamlit as st
    return st.session_state.setdefault("api_client", ApiClient())

def guard(call):
    import streamlit as st
    try: return call()
    except ApiError as exc:
        st.error(f"{exc} {f'({exc.code})' if exc.code else ''}")
        return None

def as_mapping(value):
    return value if isinstance(value, Mapping) else {}

def as_rows(value):
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, Mapping)]

def count_mapping(value):
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items() if isinstance(item, (int, float)) and not isinstance(item, bool)}

def count_value(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else 0

def metric_row(items):
    import streamlit as st
    cols=st.columns(len(items))
    for col,(label,value) in zip(cols,items):
        valid = isinstance(value, (str, int, float)) and not isinstance(value, bool)
        col.metric(label, value if valid else "—")
