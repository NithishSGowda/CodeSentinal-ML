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
from scanner.entry_detector import scan_entry_points, generate_attack_surface_summary
from ml.model import train_model, predict_risk

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

# Initialize ML Model
train_model(force=False)

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
        st.markdown("`SECURE_CORE_v3.0`")
        
        st.divider()
        st.write("### [ SYSTEM_LOG ]")
        st.success("SCANNER: ONLINE")
        st.success("ML_CORE: ONLINE")
        st.info("AUTH: BYPASSED")
        
        st.divider()
        st.markdown("### [ COMMANDS ]")
        st.write("`> INITIALIZE_SCAN`")
        st.write("`> MAP_ATTACK_SURFACE`")
        st.write("`> RUN_ML_CLASSIFIER`")
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
                # -------------------------------------------------------------
                # STATIC ANALYSIS
                # -------------------------------------------------------------
                metadata = extract_metadata(file_path, uploaded_file.name)
                stats = analyze_code_statistics(lines)
                findings = scan_vulnerabilities(lines)
                summary_msg, summary_type, base_score = generate_security_summary(findings)
                
                # -------------------------------------------------------------
                # DAY 3: ATTACK SURFACE ANALYSIS
                # -------------------------------------------------------------
                entry_findings = scan_entry_points(lines)
                attack_surface = generate_attack_surface_summary(entry_findings)
                
                # -------------------------------------------------------------
                # DAY 4: ML RISK CLASSIFICATION
                # -------------------------------------------------------------
                ml_result = predict_risk(content)
                ml_prediction = ml_result["prediction"]
                ml_confidence = ml_result["confidence"]
                
                # Adjust final security score based on ML Prediction
                final_score = base_score
                if ml_prediction == "High Risk":
                    final_score = max(0, final_score - 20)
                elif ml_prediction == "Medium Risk":
                    final_score = max(0, final_score - 10)

                # Dashboard Layout
                tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                    "[ 01_OVERVIEW ]", 
                    "[ 02_ATTACK_SURFACE ]", 
                    "[ 03_ML_PREDICTION ]", 
                    "[ 04_THREATS ]", 
                    "[ 05_ANALYTICS ]", 
                    "[ 06_RAW_CODE ]"
                ])
                
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
                            s1.metric("SECURITY_SCORE", f"{final_score}%")
                            s2.metric("FUNCS", stats["functions"])
                            s3.metric("COMM", stats["comments"])
                            
                    # Summary Alert
                    st.write("")
                    st.markdown(f"#### `> SYSTEM_SUMMARY`")
                    if final_score >= 90:
                        st.success(f"STATUS: SECURE | Final Score: {final_score}% | No immediate threats detected.")
                    elif final_score >= 60:
                        st.warning(f"STATUS: MEDIUM RISK | Final Score: {final_score}% | Potential vulnerabilities found.")
                    else:
                        st.error(f"STATUS: CRITICAL RISK | Final Score: {final_score}% | {summary_msg}")

                with tab2:
                    st.write("")
                    st.markdown("#### `> ATTACK_SURFACE_ANALYSIS`")
                    
                    # Attack Surface Metrics
                    col_as1, col_as2, col_as3, col_as4 = st.columns(4)
                    col_as1.metric("ENTRY_POINTS", attack_surface["total_entry_points"])
                    col_as2.metric("ENDPOINTS", attack_surface["total_endpoints"])
                    col_as3.metric("RISKY_UPLOADS", attack_surface["risky_uploads"])
                    col_as4.metric("HIGH_SEV_INPUTS", attack_surface["high_severity_inputs"])
                    
                    st.write("")
                    if entry_findings:
                        st.markdown("##### `> DETECTED_ENTRY_POINTS`")
                        entry_df = pd.DataFrame(entry_findings)
                        
                        def color_severity(val):
                            color = '#00FF41' # Default Green
                            if val == 'High': color = '#FF3131'
                            elif val == 'Medium': color = '#FFFF00'
                            elif val == 'Low': color = '#00FFFF'
                            elif val == 'Info': color = '#8A2BE2'
                            return f'color: {color}; font-weight: bold;'
                            
                        st.dataframe(
                            entry_df.style.applymap(color_severity, subset=['severity']),
                            use_container_width=True,
                            hide_index=True
                        )
                    else:
                        st.success("`NO_ATTACKER_ENTRY_POINTS_DETECTED`")

                with tab3:
                    st.write("")
                    st.markdown("#### `> ML_RISK_CLASSIFICATION`")
                    
                    col_ml1, col_ml2 = st.columns(2)
                    with col_ml1:
                        with st.container(border=True):
                            st.markdown("##### `> PREDICTION_RESULTS`")
                            
                            pred_color = "#00FF41"
                            if ml_prediction == "High Risk": pred_color = "#FF3131"
                            elif ml_prediction == "Medium Risk": pred_color = "#FFFF00"
                            
                            st.markdown(f"<h2 style='color:{pred_color};'>{ml_prediction}</h2>", unsafe_allow_html=True)
                            st.write(f"Confidence Score: **{ml_confidence}%**")
                            
                    with col_ml2:
                        with st.container(border=True):
                            st.markdown("##### `> CONFIDENCE_DISTRIBUTION`")
                            scores = ml_result["all_scores"]
                            if scores:
                                scores_df = pd.DataFrame(list(scores.items()), columns=['Label', 'Probability'])
                                fig_ml = px.bar(
                                    scores_df, 
                                    x='Probability', 
                                    y='Label', 
                                    orientation='h',
                                    color='Label',
                                    color_discrete_map={'Safe': '#00FF41', 'Medium Risk': '#FFFF00', 'High Risk': '#FF3131'}
                                )
                                fig_ml.update_layout(
                                    plot_bgcolor='rgba(0,0,0,0)',
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    font=dict(color='#00FF41', family='Courier New'),
                                    margin=dict(l=0, r=0, t=0, b=0),
                                    height=150
                                )
                                st.plotly_chart(fig_ml, use_container_width=True)

                with tab4:
                    st.write("")
                    st.markdown("#### `> VULNERABILITY_LOG`")
                    if findings:
                        findings_df = pd.DataFrame(findings)
                        display_df = findings_df[['severity', 'issue', 'line', 'matched_code', 'description']]
                        
                        def color_severity(val):
                            color = '#00FF41'
                            if val == 'High': color = '#FF3131'
                            elif val == 'Medium': color = '#FFFF00'
                            elif val == 'Low': color = '#00FFFF'
                            return f'color: {color}; font-weight: bold; border: 1px solid {color}; padding: 2px;'

                        st.dataframe(
                            display_df.style.applymap(color_severity, subset=['severity']),
                            use_container_width=True,
                            hide_index=True
                        )
                    else:
                        st.success("`NO_VULNERABILITIES_FOUND_IN_TARGET_OBJECT`")

                with tab5:
                    st.write("")
                    st.markdown("#### `> SECURITY_ANALYTICS`")
                    
                    col_c1, col_c2 = st.columns(2)
                    dark_layout = dict(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#00FF41', family='Courier New'),
                        xaxis=dict(gridcolor='rgba(0,255,65,0.1)', zerolinecolor='rgba(0,255,65,0.1)'),
                        yaxis=dict(gridcolor='rgba(0,255,65,0.1)', zerolinecolor='rgba(0,255,65,0.1)')
                    )
                    
                    with col_c1:
                        if findings:
                            st.markdown("##### `> VULNERABILITY_DISTRIBUTION`")
                            fig_pie = px.pie(
                                findings_df, 
                                names='severity', 
                                color='severity',
                                color_discrete_map={'High': '#FF3131', 'Medium': '#FFFF00', 'Low': '#00FFFF'},
                                hole=0.6
                            )
                            fig_pie.update_layout(dark_layout)
                            st.plotly_chart(fig_pie, use_container_width=True)
                        else:
                            st.info("`NO_VULNERABILITY_DATA`")
                            
                    with col_c2:
                        if entry_findings:
                            st.markdown("##### `> ATTACK_SURFACE_DISTRIBUTION`")
                            entry_df = pd.DataFrame(entry_findings)
                            fig_entry = px.pie(
                                entry_df,
                                names='type',
                                hole=0.6,
                                color_discrete_sequence=px.colors.sequential.Tealgrn
                            )
                            fig_entry.update_layout(dark_layout)
                            st.plotly_chart(fig_entry, use_container_width=True)
                        else:
                            st.info("`NO_ATTACK_SURFACE_DATA`")

                with tab6:
                    st.write("")
                    with st.container(border=True):
                        st.markdown(f"#### `> DATA_DUMP: {metadata['filename']}`")
                        lang = metadata['language'].lower() if metadata['language'] != "Unknown" else "python"
                        st.code(content, language=lang, line_numbers=True)

if __name__ == "__main__":
    main()
