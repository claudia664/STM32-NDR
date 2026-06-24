import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib


FEATURES = [
    ' Destination Port',
    ' Flow Duration',
    ' Total Fwd Packets',
    ' SYN Flag Count',
    ' RST Flag Count'
]

MODEL_PATH = "model_ndr.joblib"
SCALER_PATH = "scaler_ndr.joblib"



df  = pd.read_csv('Monday-WorkingHours.pcap_ISCX.csv')


# 2. Verifica ca features exista in dataset
for f in FEATURES:
    if f not in df.columns:
        print(f"EROARE: coloana '{f}' nu exista in CSV!")
        print("Coloane disponibile:", df.columns.tolist())
        exit(1)

X = df[FEATURES].copy()
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.dropna(inplace=True)


# 5. Verifici distributia feature-urilor (sanity check)
print("\n[4] Statistici features:")
print(X.describe().to_string())


# 6. Normalizezi (Isolation Forest nu e strict dependent de normalizare,
#    dar ajuta cand valorile au scale foarte diferite, ex. port 0-65535 vs flags 0-10)
print("\n[5] Normalizez features...")
scaler = StandardScaler()

X_array = X.values
X_scaled = scaler.fit_transform(X_array)


print("\n[6] Antrenez Isolation Forest...")
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)
print("    Antrenare completa!")


# 8. Validare rapida pe datele de antrenare
scores = model.decision_function(X_scaled)
predictii = model.predict(X_scaled)
anomalii = (predictii == -1).sum()
print(f"\n[7] Validare pe date de antrenare:")
print(f"    Normal (1): {(predictii == 1).sum()}")
print(f"    Anomalie (-1): {anomalii} ({anomalii/len(predictii)*100:.1f}%)")
print(f"    Score mediu: {scores.mean():.3f} (mai mare = mai normal)")
 
# 9. Salvezi modelul si scaler-ul
joblib.dump(model, MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)
print(f"\n[8] Model salvat: {MODEL_PATH}")
print(f"    Scaler salvat: {SCALER_PATH}")

