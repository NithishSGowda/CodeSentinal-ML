import streamlit as st
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scanner.detector import (
    extract_metadata, 
    analyze_code_statistics, 
    scan_vulnerabilities, 
    generate_security_summary
)

# Configure page settings
st.set_page_config(
    page_title="CodeSentinel ML | Terminal",
    page_icon="📟",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Hacker Theme CSS
st.markdown("""
<style>
    /* Main Background and Text */
    .stApp {
        background-color: #0E1117;
        color: #00FF41;
        font-family: 'Courier New', Courier, monospace;
    }
    
    /* Headers */
    .main-header {
        font-size: 3rem;
        font-weight: 900;
        margin-bottom: 0px;
        color: #00FF41;
        text-shadow: 0 0 5px rgba(0, 255, 65, 0.5); /* Reduced glow */
        letter-spacing: 2px;
    }
    .sub-header {
        font-size: 1rem;
        color: #00FF41;
        opacity: 0.7;
        margin-bottom: 2rem;
        text-transform: uppercase;
        border-bottom: 1px solid #00FF41;
        padding-bottom: 5px;
    }
    
    /* Containers and Metrics */
    div[data-testid="stMetric"] {
        background-color: rgba(0, 255, 65, 0.05);
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #00FF41;
        box-shadow: inset 0 0 5px rgba(0, 255, 65, 0.2);
    }
    div[data-testid="stMetricLabel"] {
        color: #00FF41 !important;
        font-size: 0.8rem !important;
        text-transform: uppercase;
    }
    div[data-testid="stMetricValue"] {
        color: #00FF41 !important;
        font-family: 'Courier New', Courier, monospace;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
        background-color: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        background-color: #1A1C23;
        border: 1px solid #00FF41;
        border-radius: 5px 5px 0 0;
        color: #00FF41 !important;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00FF41 !important;
        color: #0E1117 !important;
        box-shadow: 0 0 8px rgba(0, 255, 65, 0.6);
    }
    
    /* Dataframes */
    .stDataFrame {
        border: 1px solid #00FF41;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0E1117;
        border-right: 1px solid #00FF41;
    }
    
    /* Glow effect for success/error */
    .stAlert {
        background-color: #0E1117 !important;
        border: 1px solid #00FF41 !important;
        color: #00FF41 !important;
    }
    .stAlert[data-baseweb="notification"] {
        border-left: 5px solid #00FF41 !important;
    }
</style>
""", unsafe_allow_html=True)

# Constants
UPLOAD_DIR = "uploads"

# Ensure upload directory exists
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

def save_uploaded_file(uploaded_file):
    """Safely save uploaded file to the uploads directory."""
    try:
        file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    except Exception as e:
        st.error(f"SYSTEM_ERROR: {e}")
        return None

def read_file_safely(file_path):
    """Safely read file with UTF-8 decoding and handle errors."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            f.seek(0)
            lines = f.readlines()
        return content, lines
    except Exception as e:
        st.error(f"IO_ERROR: {e}")
        return None, None

def main():
    # Sidebar
    with st.sidebar:
        st.markdown("<h1 style='color:#00FF41; text-shadow: 0 0 3px rgba(0,255,65,0.3);'>_CODESENTINEL_</h1>", unsafe_allow_html=True)
        st.markdown("`SECURE_CORE_v2.0`")
        
        st.divider()
        st.write("### [ SYSTEM_LOG ]")
        st.success("SCANNER: ONLINE")
        st.warning("ML_CORE: STANDBY")
        st.info("AUTH: BYPASSED")
        
        st.divider()
        st.markdown("### [ COMMANDS ]")
        st.write("`> INITIALIZE_SCAN`")
        st.write("`> ANALYZE_VULN`")
        st.write("`> GEN_REPORT`")

    # Main Area
    st.markdown('<div class="main-header">TERMINAL@SENTINEL:~#</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Advanced Cyber-Threat Detection Interface</div>', unsafe_allow_html=True)
    
    # 1. Upload Section
    with st.container(border=True):
        st.markdown("#### `> INPUT_SOURCE_CODE`")
        allowed_types = ["py", "js", "php", "java", "txt"]
        uploaded_file = st.file_uploader("", type=allowed_types, label_visibility="collapsed")

    if uploaded_file is not None:
        file_path = save_uploaded_file(uploaded_file)
        if file_path:
            content, lines = read_file_safely(file_path)
            
            if content is not None and lines is not None:
                # Perform Analysis
                metadata = extract_metadata(file_path, uploaded_file.name)
                stats = analyze_code_statistics(lines)
                findings = scan_vulnerabilities(lines)
                summary_msg, summary_type, security_score = generate_security_summary(findings)

                # Dashboard Layout
                tab1, tab2, tab3, tab4 = st.tabs(["[ 01_OVERVIEW ]", "[ 02_THREATS ]", "[ 03_ANALYTICS ]", "[ 04_RAW_CODE ]"])
                
                with tab1:
                    st.write("")
                    col_m1, col_m2 = st.columns([1, 1])
                    
                    with col_m1:
                        with st.container(border=True):
                            st.markdown("#### `> FILE_IDENTITY`")
                            m1, m2 = st.columns(2)
                            m1.metric("OBJECT", metadata['filename'])
                            m1.metric("TYPE", metadata['language'])
                            m2.metric("SIZE", f"{metadata['size_kb']} KB")
                            m2.metric("EXT", metadata['extension'])
                    
                    with col_m2:
                        with st.container(border=True):
                            st.markdown("#### `> STATISTICS`")
                            s1, s2, s3 = st.columns(3)
                            s1.metric("LINES", stats["total_lines"])
                            s1.metric("SCORE", f"{security_score}%")
                            s2.metric("FUNCS", stats["functions"])
                            s3.metric("COMM", stats["comments"])
                            
                    # Summary Alert
                    st.write("")
                    st.markdown(f"#### `> SYSTEM_SUMMARY`")
                    if summary_type == "success":
                        st.success(f"STATUS: SECURE | {summary_msg}")
                    elif summary_type == "info":
                        st.info(f"STATUS: NOTICE | {summary_msg}")
                    elif summary_type == "warning":
                        st.warning(f"STATUS: VULNERABLE | {summary_msg}")
                    else:
                        st.error(f"STATUS: CRITICAL | {summary_msg}")

                with tab2:
                    st.write("")
                    st.markdown("#### `> VULNERABILITY_LOG`")
                    if findings:
                        findings_df = pd.DataFrame(findings)
                        display_df = findings_df[['severity', 'issue', 'line', 'matched_code', 'description']]
                        
                        # Style the severity column
                        def color_severity(val):
                            color = '#00FF41' # Default Green
                            if val == 'High': color = '#FF3131' # Neon Red
                            elif val == 'Medium': color = '#FFFF00' # Neon Yellow
                            elif val == 'Low': color = '#00FFFF' # Neon Cyan
                            return f'color: {color}; font-weight: bold; border: 1px solid {color}; padding: 2px;'

                        st.dataframe(
                            display_df.style.applymap(color_severity, subset=['severity']),
                            use_container_width=True,
                            hide_index=True
                        )
                        
                        # Download Feature
                        st.write("")
                        csv = display_df.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="[ DOWNLOAD_EXPLOIT_REPORT ]",
                            data=csv,
                            file_name=f"report_{metadata['filename']}.csv",
                            mime="text/csv",
                        )
                    else:
                        st.success("`NO_VULNERABILITIES_FOUND_IN_TARGET_OBJECT`")

                with tab3:
                    st.write("")
                    if findings:
                        findings_df = pd.DataFrame(findings)
                        col_c1, col_c2 = st.columns(2)
                        
                        # Custom Plotly Theme
                        dark_layout = dict(
                            plot_bgcolor='rgba(0,0,0,0)',
                            paper_bgcolor='rgba(0,0,0,0)',
                            font=dict(color='#00FF41', family='Courier New'),
                            xaxis=dict(gridcolor='rgba(0,255,65,0.1)', zerolinecolor='rgba(0,255,65,0.1)'),
                            yaxis=dict(gridcolor='rgba(0,255,65,0.1)', zerolinecolor='rgba(0,255,65,0.1)')
                        )
                        
                        with col_c1:
                            st.markdown("##### `> RISK_DISTRIBUTION`")
                            fig_pie = px.pie(
                                findings_df, 
                                names='severity', 
                                color='severity',
                                color_discrete_map={'High': '#FF3131', 'Medium': '#FFFF00', 'Low': '#00FFFF'},
                                hole=0.6
                            )
                            fig_pie.update_layout(dark_layout)
                            st.plotly_chart(fig_pie, use_container_width=True)
                            
                        with col_c2:
                            st.markdown("##### `> THREAT_FREQUENCY`")
                            fig_bar = px.bar(
                                findings_df['issue'].value_counts().reset_index(),
                                x='issue',
                                y='count',
                                labels={'issue': 'ID', 'count': 'FREQ'},
                                color_discrete_sequence=['#00FF41']
                            )
                            fig_bar.update_layout(dark_layout)
                            st.plotly_chart(fig_bar, use_container_width=True)
                    else:
                        st.info("`WAITING_FOR_DATA_INPUT...`")

                with tab4:
                    st.write("")
                    with st.container(border=True):
                        st.markdown(f"#### `> DATA_DUMP: {metadata['filename']}`")
                        lang = metadata['language'].lower() if metadata['language'] != "Unknown" else "python"
                        st.code(content, language=lang, line_numbers=True)

if __name__ == "__main__":
    main()
