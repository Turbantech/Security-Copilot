import time
import json
import os
import streamlit as st

MAX_REQUESTS_PER_MINUTE = 5
MAX_TOTAL_REQUESTS = 30
MAX_DAILY_REQUESTS = 150  # change this to 100 or 200 as you prefer

DAILY_COUNTER_FILE = "daily_requests.json"


def _get_daily_count() -> dict:
    today = time.strftime("%Y-%m-%d")
    if os.path.exists(DAILY_COUNTER_FILE):
        try:
            with open(DAILY_COUNTER_FILE, "r") as f:
                data = json.load(f)
            if data.get("date") == today:
                return data
        except Exception:
            pass
    return {"date": today, "count": 0}


def _increment_daily_count():
    data = _get_daily_count()
    data["count"] += 1
    with open(DAILY_COUNTER_FILE, "w") as f:
        json.dump(data, f)


def check_rate_limit():
    current_time = time.time()

    if "request_times" not in st.session_state:
        st.session_state.request_times = []
    if "total_requests" not in st.session_state:
        st.session_state.total_requests = 0

    # remove requests older than 60 seconds
    st.session_state.request_times = [
        t for t in st.session_state.request_times
        if current_time - t < 60
    ]

    # per minute limit
    if len(st.session_state.request_times) >= MAX_REQUESTS_PER_MINUTE:
        st.warning("⚠️ Too many requests. Please wait a minute.")
        st.stop()

    # per session limit
    if st.session_state.total_requests >= MAX_TOTAL_REQUESTS:
        st.warning("⚠️ Session query limit reached. Please refresh.")
        st.stop()

    # daily limit
    daily = _get_daily_count()
    if daily["count"] >= MAX_DAILY_REQUESTS:
        st.warning("⚠️ Daily request limit reached. Please come back tomorrow.")
        st.stop()

    # record request
    st.session_state.request_times.append(current_time)
    st.session_state.total_requests += 1
    _increment_daily_count()
