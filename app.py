import streamlit as st
import torch
import joblib
import pandas as pd
import numpy as np
import plotly.express as px
import os
from scapy.all import sniff, IP, TCP, ARP
from model import load_ids_model
from feature_extractor import extract_packet_features

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title=" IDS ",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ================= CONSTANTS =================
CLASSES = ['Benign', 'DDoS', 'DoS', 'Mirai', 'Recon', 'Web Attack']
CRITICAL = ["DDoS", "Mirai", "ANOMALY"]

PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    58: "ICMPv6"
}

# ================= GOD TIER UI =================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;800&family=Inter:wght@300;500;700&display=swap');

:root{
    --neon:#00f6ff;
    --danger:#ff003c;
    --glass:rgba(255,255,255,.06);
}

.stApp{
    background:
        radial-gradient(circle at 15% 20%, rgba(0,246,255,.15), transparent 30%),
        radial-gradient(circle at 85% 80%, rgba(255,0,80,.15), transparent 30%),
        linear-gradient(180deg,#02040a,#020617);
    color:#e5e7eb;
    font-family:'Inter',sans-serif;
    animation:bgFloat 30s linear infinite;
}

@keyframes bgFloat{
    0%{background-position:0% 0%,100% 100%,0% 0%}
    50%{background-position:100% 0%,0% 100%,0% 0%}
    100%{background-position:0% 0%,100% 100%,0% 0%}
}

[data-testid="stSidebar"]{
    background:rgba(3,6,20,.92);
    backdrop-filter: blur(25px);
    border-right:1px solid rgba(255,255,255,.08);
}

.header{
    text-align:center;
    font-family:'Orbitron',sans-serif;
    font-size:3.6rem;
    letter-spacing:18px;
    background:linear-gradient(90deg,var(--neon),#ffffff,var(--danger));
    background-size:300% auto;
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
    animation:headerScan 7s linear infinite;
}

@keyframes headerScan{
    to{background-position:300% center}
}

.sub{
    text-align:center;
    color:#9ca3af;
    letter-spacing:7px;
    margin-bottom:60px;
}

.card{
    position:relative;
    background:var(--glass);
    border:1px solid rgba(255,255,255,.12);
    border-radius:26px;
    padding:36px;
    text-align:center;
    backdrop-filter: blur(22px);
    box-shadow:
        inset 0 0 0.5px rgba(255,255,255,.4),
        0 30px 80px rgba(0,0,0,.8);
    transition:all .45s cubic-bezier(.22,1,.36,1);
}

.card::before{
    content:'';
    position:absolute;
    inset:0;
    border-radius:26px;
    background:linear-gradient(120deg,transparent,rgba(255,255,255,.08),transparent);
    opacity:0;
    transition:.4s;
}

.card:hover::before{
    opacity:1;
}

.card:hover{
    transform:translateY(-8px) scale(1.03);
    box-shadow:
        0 0 40px rgba(0,246,255,.4),
        0 50px 120px rgba(0,0,0,.9);
}

.danger{
    border-color:var(--danger);
    animation:dangerPulse 1.2s infinite alternate;
}

@keyframes dangerPulse{
    from{box-shadow:0 0 20px rgba(255,0,60,.5)}
    to{box-shadow:0 0 70px rgba(255,0,60,1)}
}

.title{
    font-size:.8rem;
    letter-spacing:6px;
    color:#9ca3af;
}

.value{
    font-size:3rem;
    font-family:'Orbitron',sans-serif;
    margin-top:12px;
}

.footer{
    text-align:center;
    color:#6b7280;
    margin-top:90px;
    font-size:.75rem;
    letter-spacing:6px;
}
</style>
""", unsafe_allow_html=True)

# ================= LOAD MODEL =================
@st.cache_resource
def load_all():
    model = load_ids_model("Transformer_CICIoT23.pth")
    scaler = joblib.load("scaler.save")
    return model, scaler

model, scaler = load_all()

# ================= PACKET PROCESS =================
def process_packet(pkt):
    try:
        if IP in pkt:
            sip, dip = pkt[IP].src, pkt[IP].dst
            proto = PROTO_MAP.get(pkt[IP].proto, pkt[IP].proto)
        elif ARP in pkt:
            sip, dip, proto = pkt[ARP].psrc, pkt[ARP].pdst, "ARP"
        else:
            return None

        if TCP in pkt:
            sp, dp, flags = pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags
        else:
            sp = dp = flags = "N/A"

        f = extract_packet_features(pkt)
        scaled = scaler.transform(f)

        with torch.no_grad():
            out = model(torch.FloatTensor(scaled))
            probs = torch.softmax(out, dim=1).numpy()[0]

        idx = np.argmax(probs)
        label = CLASSES[idx]
        conf = float(probs[idx]) * 100
        anomaly = label != "Benign"

        if flags == "S":
            label = "ANOMALY"
            anomaly = True
            conf = 99.9

        return label, anomaly, conf, sip, dip, sp, dp, proto
    except:
        return None

# ================= HEADER =================
st.markdown("<div class='header'>INTRUSION DETECTION SYSTEM</div>", unsafe_allow_html=True)
st.markdown("<div class='sub'>Transformer Based</div>", unsafe_allow_html=True)

# ================= SIDEBAR =================
with st.sidebar:
    st.markdown("### SECURITY OPERATIONS CORE")
    mode = st.radio("MODE", ["UPLOAD PCAP", "LIVE SNIFFING"])
    pkt_limit = st.slider("PACKET LIMIT", 100, 8000, 600)
    stop_btn = st.button("TERMINATE")

# ================= RENAME =================
def rename_columns(df):
    return df.rename(columns={
        "SEQ":"Sequence",
        "LABEL":"Label",
        "CONF":"Confidence %",
        "SRC_IP":"Source IP",
        "DST_IP":"Destination IP",
        "SRC_PORT":"Source Port",
        "DST_PORT":"Destination Port",
        "PROTO":"Protocol"
    })

# ================= UPLOAD =================
if mode == "UPLOAD PCAP":
    up = st.file_uploader("Upload PCAP File", type=["pcap","pcapng"])
    if up:
        temp = f"temp_{up.name}"
        with open(temp,"wb") as f:
            f.write(up.getbuffer())

        packets = sniff(offline=temp, count=pkt_limit)
        os.remove(temp)

        stats = {"t":0,"a":0,"b":0}
        logs = []

        for p in packets:
            res = process_packet(p)
            if not res:
                continue

            lbl, anom, conf, sip, dip, sp, dp, proto = res

            stats["t"] += 1
            stats["a"] += int(anom)
            stats["b"] += int(not anom)

            logs.append({
                "SEQ": stats["t"],
                "LABEL": lbl,
                "CONF": round(conf,2),
                "SRC_IP": sip,
                "DST_IP": dip,
                "SRC_PORT": sp,
                "DST_PORT": dp,
                "PROTO": proto
            })

        df = rename_columns(pd.DataFrame(logs))
        anomaly_df = df[df["Label"] != "Benign"]

        c1,c2,c3 = st.columns(3)
        c1.markdown(f"<div class='card'><div class='title'>TOTAL</div><div class='value'>{stats['t']}</div></div>", unsafe_allow_html=True)
        c2.markdown(f"<div class='card danger'><div class='title'>THREATS</div><div class='value'>{stats['a']}</div></div>", unsafe_allow_html=True)
        c3.markdown(f"<div class='card'><div class='title'>BENIGN</div><div class='value'>{stats['b']}</div></div>", unsafe_allow_html=True)

        fig = px.scatter(
            df, x="Sequence", y="Confidence %",
            color="Label", size="Confidence %",
            template="plotly_dark",
            title="Threat Intensity Timeline"
        )
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Packet Log")
        st.dataframe(df, use_container_width=True, height=380)

        st.markdown("### Anomaly Log")
        st.dataframe(anomaly_df, use_container_width=True, height=380)


# ================= LIVE SNIFFING =================
if mode == "LIVE SNIFFING":

    iface = "wlp1s0"   

    dash = st.empty()
    table = st.empty()
    anomaly_table = st.empty()

    if "running" not in st.session_state:
        st.session_state.running = False

    col1, col2 = st.columns(2)
    with col1:
        start = st.button("START LIVE CAPTURE")
    with col2:
        stop = st.button("STOP")

    if start:
        st.session_state.running = True
    if stop:
        st.session_state.running = False

    stats = {"t": 0, "a": 0, "b": 0}
    logs = []

    def cb(pkt):
        res = process_packet(pkt)
        if not res:
            return

        lbl, anom, conf, sip, dip, sp, dp, proto = res

        stats["t"] += 1
        stats["a"] += int(anom)
        stats["b"] += int(not anom)

        logs.append({
            "SEQ": stats["t"],
            "LABEL": lbl,
            "CONF": round(conf, 2),
            "SRC_IP": sip,
            "DST_IP": dip,
            "SRC_PORT": sp,
            "DST_PORT": dp,
            "PROTO": proto
        })

    while st.session_state.running and stats["t"] < pkt_limit:
        try:
            sniff(
                iface=iface,
                prn=cb,
                store=False,
                timeout=1
            )

            if not logs:
                continue

            df = rename_columns(pd.DataFrame(logs))
            anomaly_df = df[df["Label"] != "Benign"]

            dash.markdown(f"""
            <div style="display:flex;gap:20px">
                <div class="card"><div class="title">TOTAL</div><div class="value">{stats['t']}</div></div>
                <div class="card danger"><div class="title">THREATS</div><div class="value">{stats['a']}</div></div>
                <div class="card"><div class="title">BENIGN</div><div class="value">{stats['b']}</div></div>
            </div>
            """, unsafe_allow_html=True)

            table.dataframe(df.tail(50), use_container_width=True, height=260)
            anomaly_table.dataframe(anomaly_df.tail(50), use_container_width=True, height=260)

        except PermissionError:
            st.error("Root permission required. Use: sudo streamlit run app.py")
            break
st.markdown("<div class='footer'>TRANSFORMER AI CORE </div>", unsafe_allow_html=True)

