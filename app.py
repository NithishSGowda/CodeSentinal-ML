"""
CodeSentinel ML - Main Streamlit Dashboard
This is the entry point for the static analysis and preprocessing dashboard.
"""

import streamlit as st
import os
import pandas as pd
from scanner.detector import (
    extract_metadata, 
    analyze_code_statistics, 
    find_suspicious_keywords, 
    generate_security_summary
)

# Configure page settings
st.set_page_config(
    page_title="CodeSentinel ML",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS that respects theme colors
st.markdown("""
<style>
    .main-header {
        font-size: 2.8rem;
        font-weight: 800;
        margin-bottom: -10px;
    }
    .sub-header {
        font-size: 1.2rem;
        opacity: 0.8;
        margin-bottom: 2rem;
    }
    /* Better spacing for metrics */
    div[data-testid="stMetric"] {
        background-color: rgba(128, 128, 128, 0.1);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid rgba(128, 128, 128, 0.2);
    }
    div[data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: 700;
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
        st.error(f"Error saving file: {e}")
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
        st.error(f"Error reading file: {e}")
        return None, None

def main():
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/000000/shield.png", width=60)
        st.title("CodeSentinel")
        st.markdown("**ML-Assisted Secure Code Intelligence**")
        
        st.divider()
        st.write("### System Status")
        st.success("🟢 Core Engine: **Online**")
        st.info("⚪ ML Models: **Phase 1 (Offline)**")
        
        st.divider()
        st.markdown("<small>v1.0.0 | Enterprise Security</small>", unsafe_allow_html=True)

    # Main Area: Title & Description
    st.markdown('<div class="main-header">🛡️ CodeSentinel Engine</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Advanced Source Code Preprocessing & Static Analysis</div>', unsafe_allow_html=True)
    
    # 1. Upload Section
    upload_container = st.container(border=True)
    with upload_container:
        st.markdown("#### 📁 Upload Source Code for Inspection")
        allowed_types = ["py", "js", "php", "java", "txt"]
        uploaded_file = st.file_uploader("Select a file for security scanning", type=allowed_types, label_visibility="collapsed")

    if uploaded_file is not None:
        file_path = save_uploaded_file(uploaded_file)
        if file_path:
            content, lines = read_file_safely(file_path)
            
            if content is not None and lines is not None:
                st.toast(f"Successfully processed: {uploaded_file.name}", icon="✅")
                
                # Perform Analysis
                metadata = extract_metadata(file_path, uploaded_file.name)
                stats = analyze_code_statistics(lines)
                findings = find_suspicious_keywords(content)
                total_findings = sum(findings.values())
                summary_msg, summary_type = generate_security_summary(total_findings)

                st.write("") # Spacer
                
                # Use Tabs for a cleaner layout
                tab1, tab2, tab3 = st.tabs(["📊 Overview & Stats", "🚨 Security Indicators", "💻 Source Code"])
                
                with tab1:
                    st.write("")
                    metadata_container = st.container(border=True)
                    with metadata_container:
                        st.markdown("#### 📄 File Identity")
                        m1, m2, m3, m4 = st.columns(4)
                        m1.metric("Filename", metadata['filename'])
                        m2.metric("Language", metadata['language'])
                        m3.metric("Extension", metadata['extension'])
                        m4.metric("Size", f"{metadata['size_kb']} KB")
                    
                    stats_container = st.container(border=True)
                    with stats_container:
                        st.markdown("#### 📈 Code Composition")
                        c1, c2, c3, c4, c5 = st.columns(5)
                        c1.metric("Total Lines", stats["total_lines"])
                        c2.metric("Blank Lines", stats["blank_lines"])
                        c3.metric("Comments", stats["comments"])
                        c4.metric("Imports", stats["imports"])
                        c5.metric("Functions", stats["functions"])
                        
                        # Add a quick visualization chart for code composition
                        st.write("")
                        chart_data = pd.DataFrame(
                            [
                                {"Component": "Blank Lines", "Count": stats["blank_lines"]},
                                {"Component": "Comments", "Count": stats["comments"]},
                                {"Component": "Imports", "Count": stats["imports"]},
                                {"Component": "Functions", "Count": stats["functions"]},
                                {"Component": "Classes", "Count": stats["classes"]}
                            ]
                        ).set_index("Component")
                        st.bar_chart(chart_data, height=200)
                    
                with tab2:
                    st.write("")
                    summary_container = st.container(border=True)
                    with summary_container:
                        st.markdown("#### 🛡️ Threat Intelligence Summary")
                        # Summary Message
                        if summary_type == "success":
                            st.success(f"**Status: SAFE** — {summary_msg}")
                        elif summary_type == "warning":
                            st.warning(f"**Status: ATTENTION** — {summary_msg}")
                        else:
                            st.error(f"**Status: CRITICAL** — {summary_msg}")

                    findings_container = st.container(border=True)
                    with findings_container:
                        st.markdown("#### 🔍 Suspicious Syntax & Hardcoded Secrets")
                        if findings:
                            findings_df = pd.DataFrame(list(findings.items()), columns=["Keyword", "Occurrences"]).sort_values(by="Occurrences", ascending=False)
                            
                            col_a, col_b = st.columns([1, 2])
                            with col_a:
                                st.dataframe(
                                    findings_df.style.background_gradient(cmap='Reds'), 
                                    hide_index=True, 
                                    use_container_width=True
                                )
                            with col_b:
                                findings_chart = findings_df.set_index("Keyword")
                                st.bar_chart(findings_chart, height=250, color="#FF4B4B")
                        else:
                            st.info("✅ Code scan completed. No recognized malicious keywords or secrets detected.")

                with tab3:
                    st.write("")
                    code_container = st.container(border=True)
                    with code_container:
                        st.markdown("#### 💻 Raw Source View")
                        lang_for_code_block = metadata['language'].lower()
                        if lang_for_code_block == "text/unknown":
                            lang_for_code_block = "text"
                        
                        st.code(content, language=lang_for_code_block)

if __name__ == "__main__":
    main()
