import streamlit as st
from config import Config
from orchestrator import SecurityCopilot
from rate_limiter import check_rate_limit
from report_generator import generate_report

# --- Page Config ---
st.set_page_config(
    page_title="Security Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)
# --- Custom CSS ---
st.markdown("""
<style>
    .stApp { background-color: #0e1117; }
    .tool-badge { 
        display: inline-block; padding: 4px 12px; border-radius: 12px; 
        font-size: 0.8rem; margin: 2px 4px; font-weight: 500;
    }
    .tool-connected { background-color: #1a3a2a; color: #4ade80; border: 1px solid #166534; }
    .tool-disconnected { background-color: #3a1a1a; color: #f87171; border: 1px solid #991b1b; }
    .risk-critical { color: #ef4444; font-weight: bold; }
    .risk-high { color: #f97316; font-weight: bold; }
    .risk-medium { color: #eab308; font-weight: bold; }
    .risk-low { color: #22c55e; font-weight: bold; }
    div[data-testid="stChatMessage"] { border-radius: 12px; }

    /* Small report button */
    div[data-testid="stButton"] > button[kind="primary"] {
        padding: 4px 16px !important;
        font-size: 0.8rem !important;
        width: auto !important;
        height: auto !important;
    }
</style>
""", unsafe_allow_html=True)

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ Security Copilot")
    st.markdown("AI-powered threat intelligence assistant")
    st.markdown("""
        <style>
        hr {
            margin-top: 8px !important;
            margin-bottom: 8px !important;
        }
        </style>
        """, unsafe_allow_html=True)

    # Tool status
    st.markdown("### 🔌 Connected Tools")
    status = Config.get_status()
    for tool, connected in status.items():
        badge_class = "tool-connected" if connected else "tool-disconnected"
        icon = "✅" if connected else "❌"
        st.markdown(f'<span class="tool-badge {badge_class}">{icon} {tool}</span>',
                    unsafe_allow_html=True)

    missing = Config.validate()
    if missing:
        st.divider()
        st.warning(f"Missing API keys: {', '.join(missing)}\n\nSet them in your `.env` file.")


    st.markdown("""
        <style>
        hr {
            margin-top: 8px !important;
            margin-bottom: 8px !important;
        }
        </style>
        """, unsafe_allow_html=True)
    
    if st.button("🗑️ Clear Chat", use_container_width=True):
        st.session_state.messages = []
        st.session_state.last_scan_data = {}
        if "copilot" in st.session_state:
            st.session_state.copilot.reset()
        st.rerun()

# --- Initialize ---
if "copilot" not in st.session_state:
    st.session_state.copilot = SecurityCopilot()
if "messages" not in st.session_state:
    st.session_state.messages = []

# --- Header ---
st.markdown("# 🛡️ Security Copilot")
col1, col2 = st.columns([6, 1])
with col1:
    st.markdown("*Ask me about any IP, URL, file hash, or MITRE ATT&CK technique.*")
with col2:
    st.link_button("📋 Guide", "https://github.com/YOUR_USERNAME/security-copilot#readme")
st.divider()

# --- File Upload ---
# --- File/IOC Input Dialog ---
@st.dialog("📂 Add IOCs or File")
def ioc_input_dialog():
    uploaded = st.file_uploader(
        "Upload file",
        type=["txt", "csv", "json"],
        label_visibility="collapsed",
    )

    if st.button("✅ Load & Close", use_container_width=True):
        content = ""
        name = ""

        if uploaded is not None:
            try:
                content = uploaded.read().decode("utf-8")
                name = uploaded.name
            except Exception as e:
                st.error(f"Could not read file: {e}")
                return

        elif pasted.strip():
            content = pasted.strip()
            name = "pasted input"

        if content:
            st.session_state.file_context = f"\n\nUser provided IOCs from {name}:\n{content[:3000]}"
            st.session_state.file_loaded_name = name
            st.rerun()
        else:
            st.warning("Please paste some text or upload a file first.")

# Initialize file context in session state
if "file_context" not in st.session_state:
    st.session_state.file_context = ""
if "file_loaded_name" not in st.session_state:
    st.session_state.file_loaded_name = ""

# --- 📎 Button + status row ---
col1, col2 = st.columns([1, 8])
with col1:
    if st.button("📎 Attach", use_container_width=True):
        ioc_input_dialog()
with col2:
    if st.session_state.file_loaded_name:
        st.success(f"✅ Loaded: {st.session_state.file_loaded_name}  |  [Clear](javascript:void(0))")
        if st.button("❌ Clear file", key="clear_file"):
            st.session_state.file_context = ""
            st.session_state.file_loaded_name = ""
            st.rerun()
# --- Chat History ---
for msg in st.session_state.messages:
    with st.chat_message(msg["role"], avatar="🧑‍💻" if msg["role"] == "user" else "🛡️"):
        st.markdown(msg["content"])

# --- Handle input (from text box or sidebar button) ---
user_input = st.chat_input("Enter an IP, URL, hash, or ask about a MITRE technique...")

if "pending_query" in st.session_state:
    user_input = st.session_state.pop("pending_query")

if user_input:
    check_rate_limit()

    # Combine user message with file content if a file was uploaded
    full_input = user_input + st.session_state.file_context if st.session_state.file_context else user_input

    # Show user message (only show typed part, not raw file dump)
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user", avatar="🧑‍💻"):
        st.markdown(user_input)

    # Get response
    with st.chat_message("assistant", avatar="🛡️"):
        with st.spinner("🔍 Querying intelligence sources..."):
            try:
                response = st.session_state.copilot.chat(full_input)
                st.markdown(response)
                st.session_state.messages.append({"role": "assistant", "content": response})

                # Show report button if a scan was performed
                scan_data = st.session_state.copilot.get_last_scan_data()
                if scan_data.get("vt_result"):
                    st.session_state.last_scan_data = scan_data

            except Exception as e:
                error_msg = f"⚠️ Error: {str(e)}"
                st.error(error_msg)
                st.session_state.messages.append({"role": "assistant", "content": error_msg})

# Show report download button if scan data exists
# Show report download button if scan data exists
# Show report download button if scan data exists
if st.session_state.get("last_scan_data"):
    scan_data = st.session_state.last_scan_data
    indicator = scan_data.get("indicator", "report")

    st.markdown('<div style="text-align:right; margin-top:-10px;">', unsafe_allow_html=True)
    
    col1, col2 = st.columns([8, 1])
    with col2:
        if st.button("📄 Report", type="primary", use_container_width=True):
            with st.spinner("Generating..."):
                try:
                    pdf_bytes = generate_report(scan_data)
                    st.download_button(
                        label="⬇️ Download",
                        data=pdf_bytes,
                        file_name=f"threat_report_{indicator.replace('.', '_')}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
                except Exception as e:
                    st.error(f"Report generation failed: {e}")
    
    st.markdown('</div>', unsafe_allow_html=True)