"""
Test rapid model NDR - verifica daca Isolation Forest
detecteaza corect trafic normal vs port scan.

Rulare: python test_model.py
"""

import joblib
import numpy as np

model  = joblib.load("model_ndr.joblib")
scaler = joblib.load("scaler_ndr.joblib")

# Features: [dst_port, flow_duration_us, total_packets, syn_count, rst_count]

teste = [
    # (descriere, features)
    ("Trafic NORMAL - HTTP (10 pachete, fara SYN flood)",
     [80, 1500000, 10, 1, 0]),

    ("Trafic NORMAL - HTTPS (5 pachete)",
     [443, 800000, 5, 1, 0]),

    ("Trafic NORMAL - DNS (3 pachete UDP)",
     [53, 500000, 3, 0, 0]),

    ("PORT SCAN - 100 SYN pe porturi diferite in 2 secunde",
     [445, 1800000, 100, 95, 2]),

    ("PORT SCAN - agresiv, 200 SYN",
     [22, 1900000, 200, 198, 1]),

    ("UDP FLOOD - 150 pachete in 2 secunde",
     [9000, 1950000, 150, 0, 0]),
]

print("=" * 60)
print("TEST MODEL NDR - ISOLATION FOREST")
print("=" * 60)

for descriere, features in teste:
    f = np.array([features])
    f_scaled = scaler.transform(f)
    predictie = model.predict(f_scaled)[0]
    score = model.decision_function(f_scaled)[0]

    verdict = "✓ NORMAL  " if predictie == 1 else "⚠ ANOMALIE"
    print(f"\n{verdict} (score={score:.3f})")
    print(f"  {descriere}")
    print(f"  Features: port={features[0]}, dur={features[1]}us, "
          f"pkts={features[2]}, SYN={features[3]}, RST={features[4]}")

print("\n" + "=" * 60)