import streamlit as st
import joblib
import pandas as pd
from feature_extraction import extract_features

# ---------------------- Load Model ----------------------
model_data = joblib.load("models/fake_site_final.pkl")
scaler = model_data["scaler"]
model = model_data["model"]
feature_names = model_data["features"]

# ---------------------- Streamlit UI ----------------------
st.title("🛡️ WebGuard - Fake Website Detector")
st.write("Enter a website URL to check if it's genuine or phishing.")

url_input = st.text_input("🔗 Enter URL:")

if st.button("Check"):
    if url_input.strip():
        with st.spinner("🔍 Analyzing the website..."):
            try:
                # Extract features
                features = extract_features(url_input)
                input_df = pd.DataFrame([features])[feature_names]

                # Debug info
                st.subheader("🧩 Feature Vector (Raw):")
                st.write(input_df.T)

                # Scale features
                scaled = scaler.transform(input_df)
                probs = model.predict_proba(scaled)[0]
                prediction = model.predict(scaled)[0]

                
                phishing_prob = probs[0]
                legit_prob = probs[1]
                confidence = round(max(phishing_prob, legit_prob) * 100, 2)

                # Debug info
                st.subheader("📊 Model Debug Info:")
                st.write(f"Probability - Phishing (0): {probs[0]:.4f}")
                st.write(f"Probability - Legitimate (1): {probs[1]:.4f}")
                st.write(f"Model Raw Prediction: {prediction}")

                # Final Verdict based on model output
                st.subheader("🚦 Final Verdict:")
                if prediction == 1:
                    st.success(f"✅ Legitimate Website (Confidence: {confidence}%)")
                else:
                    st.error(f"🚨 Phishing Website Detected! (confidence: {confidence}%)")

            except Exception as e:
                st.error(f"❌ Error analyzing URL: {e}")
    else:
        st.warning("⚠️ Please enter a URL first.")
