import streamlit as st
import pandas as pd
import os
import json
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="AI Smart Firewall Dashboard", page_icon="🛡️", layout="wide")

# Theme and styling
st.markdown("""
<style>
    .threat-critical { color: #d32f2f; font-weight: bold; }
    .threat-warn { color: #f57c00; font-weight: bold; }
    .threat-safe { color: #388e3c; font-weight: bold; }
    .block-card { background-color: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 5px solid #d32f2f; margin-bottom: 10px; }
    .warn-card { background-color: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 5px solid #f57c00; margin-bottom: 10px; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Multi-Layer AI Smart Firewall")
st.markdown("Advanced Predictive Cyber Protection & Threat Analytics")

# Load Logs
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_file_path = os.path.join(base_dir, "logs", "firewall_events.jsonl")

def load_logs():
    if not os.path.exists(log_file_path):
        return pd.DataFrame()
    data = []
    with open(log_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not data:
        return pd.DataFrame()
        
    df = pd.DataFrame(data)
    # Expand details dict into columns
    details_df = pd.json_normalize(df['details'])
    df = pd.concat([df.drop(['details'], axis=1), details_df], axis=1)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

df = load_logs()

if df.empty:
    st.info("No firewall events logged yet. Route traffic through the proxy (port 5000) to see analytics.")
    st.stop()

# Sidebar Navigation
st.sidebar.title("🛡️ Firewall Navigation")
page = st.sidebar.radio("Go to", ["Overview", "Website Risk Analysis"])

if page == "Website Risk Analysis":
    st.header("Website Risk Analysis")
    st.markdown("Select a recently analyzed website to view its detailed security breakdown.")
    
    if not df.empty:
        # Create a dropdown to select URL
        urls = df['url'].unique()
        selected_url = st.selectbox("Select Website URL", urls)
        
        if selected_url:
            # Get the most recent scan for this URL
            url_data = df[df['url'] == selected_url].sort_values(by='timestamp', ascending=False).iloc[0]
            
            st.subheader(f"Analysis for: {selected_url}")
            
            category = url_data.get('Category', 'UNKNOWN')
            
            try:
                risk_score = float(url_data.get('risk_score', 0.0))
            except:
                risk_score = 0.0
                
            c1, c2 = st.columns(2)
            c1.metric("Detected Category", category)
            c2.metric("Final Risk Score", f"{risk_score:.2f}")
            
            st.markdown("### Reasons for Flagging / Blocking")
            reasons = url_data.get('Reasons', [])
            if isinstance(reasons, list) and reasons:
                for r in reasons:
                    st.markdown(f"• {r}")
            elif isinstance(reasons, str):
                try:
                    # In case it's a string representation of a list
                    parsed = eval(reasons)
                    if isinstance(parsed, list):
                        for r in parsed:
                            st.markdown(f"• {r}")
                    else:
                        st.markdown(f"• {reasons}")
                except:
                    st.markdown(f"• {reasons}")
            else:
                st.markdown("• No specific reasons recorded for this risk footprint.")
                
            st.markdown("### Detection Modules Triggered")
            modules = []
            
            def check_mod(col, thresh):
                val = url_data.get(col)
                return pd.notna(val) and float(val) > thresh
                
            if check_mod('AI_Score', 0.3): modules.append("Phishing Detector (ML Model)")
            if check_mod('Piracy_Score', 0.2): modules.append("Piracy Detector")
            if check_mod('Malware_UI_Score', 0.2): modules.append("Content Security Analyzer")
            if check_mod('Domain_Reputation', 0.3): modules.append("Domain Intelligence")
            if check_mod('HTML_Content', 0.3): modules.append("HTML Content Analyzer")
            if check_mod('Heuristics', 0.3): modules.append("Heuristic Security Layer")
            
            if modules:
                for m in modules:
                    st.markdown(f"✅ {m}")
            else:
                st.markdown("No major modules triggered (Safe status).")
                
    st.stop()


# 1. Real-Time Metrics
st.header("1. Real-Time Security Metrics")
total_reqs = len(df)
blocked = len(df[df['decision'] == 'BLOCK'])
warned = len(df[df['decision'] == 'WARN'])
allowed = len(df[df['decision'] == 'ALLOW'])

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Requests Intercepted", total_reqs)
col2.metric("Allowed Traffic", allowed)
col3.metric("Warning Alerts", warned)
col4.metric("Blocked Threats", blocked)

st.divider()

# 3. Threat Analytics Charts
st.header("2. Threat Analytics")
col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    # Traffic Breakdown Pie Chart
    traffic_labels = ['ALLOW', 'WARN', 'BLOCK']
    traffic_values = [allowed, warned, blocked]
    fig_pie = px.pie(
        names=traffic_labels, 
        values=traffic_values,
        title="Traffic Policy Decisions",
        color=traffic_labels,
        color_discrete_map={'ALLOW':'#388e3c', 'WARN':'#f57c00', 'BLOCK':'#d32f2f'},
        hole=0.4
    )
    st.plotly_chart(fig_pie, use_container_width=True)

with col_chart2:
    # Risk Score Distribution
    fig_hist = px.histogram(
        df, x="risk_score", nbins=10, 
        title="URL Risk Score Distribution",
        labels={"risk_score": "Risk Score (0=Safe, 1=Critical)"},
        color="decision",
        color_discrete_map={'ALLOW':'#388e3c', 'WARN':'#f57c00', 'BLOCK':'#d32f2f'}
    )
    st.plotly_chart(fig_hist, use_container_width=True)

st.divider()

# Layers Breakdown (Averages)
st.subheader("Average Threat Vectors Detected")
if 'AI_Score' in df.columns:
    col_v1, col_v2, col_v3, col_v4 = st.columns(4)
    df_threats = df[df['decision'].isin(['BLOCK', 'WARN'])]
    if not df_threats.empty:
        col_v1.metric("Avg AI Phishing Confidence", f"{df_threats['AI_Score'].mean():.2f}")
        col_v2.metric("Avg Domain Risk (Age/TLD)", f"{df_threats.get('Domain_Reputation', pd.Series([0])).mean():.2f}")
        col_v3.metric("Avg Suspicious Heuristics", f"{df_threats.get('Heuristics', pd.Series([0])).mean():.2f}")
        col_v4.metric("Avg HTML Content Risk", f"{df_threats.get('HTML_Content', pd.Series([0])).mean():.2f}")


st.divider()

# Explainable AI Panel
st.header("3. Explainable AI Panel (XAI)")
st.markdown("Deep dive into *why* the Multi-Layer Intelligence Engine made its decisions.")

df_flags = df[df['decision'].isin(['BLOCK', 'WARN'])].sort_values(by='timestamp', ascending=False)

if df_flags.empty:
    st.success("No threats detected recently.")
else:
    for _, row in df_flags.head(10).iterrows(): # Show top 10 recent threats
        css_class = "block-card" if row['decision'] == 'BLOCK' else "warn-card"
        icon = "⛔" if row['decision'] == 'BLOCK' else "⚠"
        
        with st.container():
            st.markdown(f'<div class="{css_class}">', unsafe_allow_html=True)
            st.markdown(f"**{icon} {row['decision']}** - `{row['url']}` (Overall Risk: **{row['risk_score']:.2f}**)")
            
            reasons = []
            if row.get('AI_Score', 0) > 0.6:
                reasons.append(f"• **AI Prediction**: High probability ({row['AI_Score']:.2f}) of phishing signature.")
            if row.get('Domain_Reputation', 0) > 0.4:
                reasons.append(f"• **Domain Risk**: Suspicious WHOIS age or TLD detected ({row['Domain_Reputation']:.2f}).")
            if row.get('Heuristics', 0) > 0.4:
                reasons.append(f"• **Heuristic Pattern**: Unusual length, many subdomains, or suspicious keywords found.")
            if row.get('HTML_Content', 0) > 0.3:
                reasons.append(f"• **Content Analysis**: Dangerous HTML found (e.g. hidden elements, fake login forms).")
            if row.get('Piracy_Score', 0) > 0.3:
                piracy_rs = ", ".join(row.get('Piracy_Reasons', [])) if isinstance(row.get('Piracy_Reasons'), list) else row.get('Piracy_Reasons', '')
                reasons.append(f"• **Piracy Indicator**: {piracy_rs}")
            if row.get('Malware_UI_Score', 0) > 0.2:
                malware_ui_rs = ", ".join(row.get('Malware_UI_Reasons', [])) if isinstance(row.get('Malware_UI_Reasons'), list) else row.get('Malware_UI_Reasons', '')
                reasons.append(f"• **Malware UI/Ads**: {malware_ui_rs}")
                
            if reasons:
                st.markdown("**Reasons for Action:**")
                for r in reasons:
                    st.markdown(r)
            else:
                st.markdown("*Blocked by combined aggregate score.*")
            
            st.markdown('</div>', unsafe_allow_html=True)

st.divider()

# 2. Recent Blocked Websites Table
st.header("4. Complete Firewall Event Log")
st.dataframe(
    df.sort_values(by='timestamp', ascending=False)[['timestamp', 'decision', 'risk_score', 'url', 'AI_Score', 'Domain_Reputation', 'Heuristics', 'HTML_Content', 'Piracy_Score', 'Malware_UI_Score']],
    use_container_width=True,
    column_config={
        "risk_score": st.column_config.ProgressColumn(
            "Final Risk Score",
            help="Aggregate Multi-Layer Risk",
            format="%.2f",
            min_value=0,
            max_value=1,
        )
    }
)
