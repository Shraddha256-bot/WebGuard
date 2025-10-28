# 🛡️ WebGuard - Fake Website Detection System

**WebGuard** is an intelligent phishing detection system that analyzes website URLs using 30+ handcrafted features to identify whether a site is **Legitimate** or **Phishing**.

### 🚀 Features
- Real-time website analysis via URL
- ML-based prediction using Random Forest
- Confidence scoring for predictions
- Intuitive Streamlit UI

### 🧠 Tech Stack
- Python, Streamlit
- Scikit-learn (RandomForestClassifier)
- Feature engineering from website metadata
- StandardScaler preprocessing

### 🧩 Model Performance
| Metric | Score |
|---------|--------|
| Accuracy | 97% |
| Precision | 0.97 |
| Recall | 0.97 |

### ⚙️ Run Locally
```bash
pip install -r requirements.txt
streamlit run app.py
