import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.svm import OneClassSVM
import os

# --- 1. CONFIGURATION AND FEATURE LIST (Phase 1: Feature Engineering) ---

FEATURE_COLUMNS = [
    'RSSI_MEAN', 'RSSI_VARIANCE', 'PROBE_FREQ_RATE', 
    'OUI_TRUST_SCORE', 'PROTOCOL_ANOMALY_FLAG',
]
PCA_VARIANCE_THRESHOLD = 0.95 
NU_PARAMETER = 0.01  # OC-SVM Hyperparameter: Sets a tight boundary for "normal"

def generate_synthetic_normal_data(num_samples):
    """Generates synthetic benign data (X_train)."""
    data = {
        'RSSI_MEAN': np.random.normal(loc=-65, scale=5, size=num_samples), 
        'RSSI_VARIANCE': np.random.uniform(low=0.1, high=3.0, size=num_samples),
        'PROBE_FREQ_RATE': np.random.randint(low=2, high=15, size=num_samples),
        'OUI_TRUST_SCORE': np.random.randint(low=8, high=11, size=num_samples),
        'PROTOCOL_ANOMALY_FLAG': np.zeros(num_samples, dtype=int),
    }
    return pd.DataFrame(data, columns=FEATURE_COLUMNS)

# --- 2. DATA PREPROCESSING (Phase 2) ---

def preprocess_data(X_train):
    """Handles scaling and dimensionality reduction."""
    
    # 1. Feature Scaling (Standardization)
    print("1. Applying StandardScaler (Normalizing features)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    joblib.dump(scaler, 'whispr_scaler.pkl')
    print("   -> Saved 'whispr_scaler.pkl'")

    # 2. Dimensionality Reduction (PCA)
    print(f"2. Applying PCA (reducing dimensions while retaining {PCA_VARIANCE_THRESHOLD*100}% variance)...")
    pca = PCA(n_components=PCA_VARIANCE_THRESHOLD)
    X_train_reduced = pca.fit_transform(X_train_scaled)
    joblib.dump(pca, 'whispr_pca.pkl')
    
    print(f"   -> Reduced features from {X_train.shape[1]} to {X_train_reduced.shape[1]} dimensions.")
    print("   -> Saved 'whispr_pca.pkl'")

    return X_train_reduced

# --- 3. MODEL TRAINING (Phase 3) ---

def train_oc_svm(X_train_reduced):
    """Initializes, trains, and saves the One-Class SVM model."""
    
    # 1. Initialize OC-SVM
    print(f"3. Training One-Class SVM (nu={NU_PARAMETER})...")
    model = OneClassSVM(
        kernel='rbf',               # Use RBF for complex, non-linear boundaries
        nu=NU_PARAMETER,            # Set model sensitivity/tightness
        gamma='scale'               # Automatically determine the kernel width
    )
    
    # 2. Train the Model
    model.fit(X_train_reduced)
    
    # 3. Save the Trained Model
    joblib.dump(model, 'whispr_model.pkl')
    print("   -> Saved 'whispr_model.pkl'")
    
    return model

# --- 4. EXECUTION ---

if __name__ == '__main__':
    print("--- Starting WHISPR AI Core Build ---")
    
    # Phase 1: Data Generation
    df_normal = generate_synthetic_normal_data(num_samples=500) 
    X_train_raw = df_normal.to_numpy()
    
    # Phase 2: Preprocessing
    X_train_final = preprocess_data(X_train_raw)
    
    # Phase 3: Training
    trained_model = train_oc_svm(X_train_final)

    print("\n[SUCCESS] AI Core Build Complete.")
    print("The three model files (.pkl) are ready for deployment into your application.")

    # Show a simple test result (using the model just trained in memory)
    # This sample represents an extreme anomaly (high variance, low trust score)
    test_anomaly = np.array([-30.0, 20.0, 150, 1, 1]).reshape(1, -1)
    
    # We must re-run the pipeline on the test data manually for a clean demonstration:
    # (In a real app, you would load the saved .pkl files)
    
    # 1. Scale test data (using the scaler fitted on normal data)
    scaler_test = joblib.load('whispr_scaler.pkl')
    test_scaled = scaler_test.transform(test_anomaly)
    
    # 2. Reduce test data (using the pca fitted on normal data)
    pca_test = joblib.load('whispr_pca.pkl')
    test_processed = pca_test.transform(test_scaled)
    
    # 3. Predict score
    anomaly_score = trained_model.decision_function(test_processed)[0]
    
    print("\n--- Final Model Validation ---")
    print(f"Score for a synthetic threat (-30dBm, high variance, low OUI): {anomaly_score:.4f}")
    if anomaly_score < 0:
        print("Model correctly classified signal as an ANOMALY (Threat).")
    else:
        print("Model incorrectly classified signal as BENIGN (Error).")
