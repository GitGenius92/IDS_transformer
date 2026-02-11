🚨 AI Powered Intrusion Detection System (IDS) – Streamlit Dashboard

An advanced **AI-based Network Intrusion Detection System** built using **Deep Learning Transformer Model**, **Streamlit Dashboard**, and **Real-Time Packet Sniffing** using Scapy.

This system detects malicious network traffic such as **DDoS, DoS, Mirai, Recon, and Web Attacks** in real-time and displays results in a premium interactive dashboard.

---

 📌 Features

✅ Real-time Network Packet Monitoring  
✅ Transformer Deep Learning Model  
✅ Multi-class Attack Detection  
✅ Premium Streamlit SOC Dashboard UI  
✅ Live Packet Feature Extraction  
✅ Traffic Visualization using Plotly  
✅ Scalable and Lightweight Deployment  

---

 🧠 Attack Classes Detected

- Benign Traffic
- DDoS Attack
- DoS Attack
- Mirai Botnet
- Reconnaissance Attack
- Web Attack
- Anomaly Detection

---

 🛠️ Tech Stack

 🔹 Frontend
- Streamlit
- Plotly Visualization
- Custom CSS Glass UI
 🔹 Backend
- Python
- Scapy (Packet Sniffing)
- PyTorch (Deep Learning Model)
- Joblib (Scaler Loading)
- Pandas & NumPy

---

 📂 Project Structure

IDS Streamlit/
│
├── app.py # Main Streamlit Dashboard
├── model.py # Transformer Model Loader
├── feature_extractor.py # Packet Feature Extraction
├── Transformer_CICIoT23.pth # Trained Deep Learning Model
├── scaler.save # Feature Scaler


---
 📊 Dataset Used

Model is trained using:

👉 **CICIoT23 Dataset**

This dataset contains modern IoT network traffic including multiple attack types.

---
 ⚙️ Installation & Setup

 1️⃣ Clone Repository

```bash
git clone https://github.com/yourusername/IDS-Streamlit.git
cd IDS-Streamlit
2️⃣ Create Virtual Environment
python -m venv venv
Activate environment:

Windows
venv\Scripts\activate
Linux / Mac
source venv/bin/activate
3️⃣ Install Dependencies
pip install -r requirements.txt
If requirements file not available, install manually:

pip install streamlit torch scapy pandas numpy plotly joblib
🚀 Running the Application
streamlit run app.py
Dashboard will open automatically in your browser.

📡 How It Works
System captures live packets using Scapy.

Extracts important network features.

Features are normalized using saved scaler.

Transformer Model predicts attack class.

Dashboard displays results in real-time.

🧪 Model Details
Parameter	Value
Model Type	Transformer
Framework	PyTorch
Dataset	CICIoT23
Output Classes	6 Attack Categories
Scaling	Standard Feature Scaling
📷 Dashboard Preview
(Add screenshots here after deployment)

🔐 Security Applications
SOC Monitoring

Enterprise Network Security

IoT Device Protection

Real-Time Attack Detection

Threat Intelligence Systems

📈 Future Improvements
Integration with SIEM Systems

Alert Notifications (Email / WhatsApp / SMS)

Cloud Deployment

Automated Threat Response

Explainable AI (SHAP / LIME Integration)

🤝 Contribution
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

📜 License
This project is for educational and research purposes.

👨‍💻 Author
Muhammad Faizan
