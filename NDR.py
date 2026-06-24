# """
# NDR Backend - citeste de la STM32 pe UART, calculeaza features
# pe ferestre de 2 secunde, ruleaza Isolation Forest.

# Formatul asteptat de la STM32 pe UART (un rand per pachet):
#   NDR,TCP,<src_port>,<dst_port>,<flags>,<length>
#   NDR,UDP,<src_port>,<dst_port>,0,<length>
#   NDR,ICMP,0,0,0,<length>

# Exemplu:
#   NDR,TCP,12345,80,S,60
#   NDR,TCP,12346,443,SA,74
#   NDR,UDP,5000,53,0,42

# Flags TCP (litera unica):
#   S = SYN
#   R = RST
#   A = ACK
#   F = FIN
#   P = PSH
#   combinatii: SA = SYN+ACK, etc.

# Rulare:
#   pip install pyserial scikit-learn joblib
#   python ndr_backend.py
# """

# import serial
# import serial.tools.list_ports
# import joblib
# import numpy as np
# import time
# from collections import defaultdict
# from datetime import datetime

# ==================================================================================================


#3.0 importuri si hashmapul pentru agregarea pachetelor
import serial
import serial.tools.list_ports
import joblib
import numpy as np
import time
from collections import defaultdict
from datetime import datetime

features = defaultdict(list)  # hashmap pentru agregarea pachetelor pe fereastra de 2 secunde
features = {
    "dest_port": [],
    "flow_duration": [],
    "total_fdw_packets": [],
    "syn_flag_count": [],
    "rst_flag_count": []
    }


#3.1 incarcam modelul si scaler-ul
model  = joblib.load("model_ndr.joblib")
scaler = joblib.load("scaler_ndr.joblib")


#3.2 deschidem portul serial
port = serial.Serial("COM7", 115200, timeout=1) #timeout=1 pentru ca nu blocheaza citirea daca nu vin date

#3.3 citim datele de pe uart
def parsare_date(line):
    line = line.strip()
    if not line.startswith("NDR,"):
        return None
    parts = line.split(",")
    if len(parts) < 6:
        return None
    try:
        return {
            "proto":   parts[1],
            "sport":   int(parts[2]),
            "dport":   int(parts[3]),
            "flags":   parts[4],
            "length":  int(parts[5]),
            "time":    time.time()
        }
    except (ValueError, IndexError):
        return None
    



#3.4 calculam features pentru fiecare pachet citit si le adaugam in hashmap
def calculeaza_features(pachete):
    if not pachete:
        return None

    dst_port    = pachete[-1]["dport"]   # portul destinatie al ultimului pachet
    total_pkts  = len(pachete)

    # Flow Duration in microsecunde (ca in CICIDS2017)
    if len(pachete) > 1:
        flow_dur = (pachete[-1]["time"] - pachete[0]["time"]) * 1_000_000
    else:
        flow_dur = 0

    syn_count   = sum(1 for p in pachete if "S" in p["flags"])
    rst_count   = sum(1 for p in pachete if "R" in p["flags"])

    return np.array([[dst_port, flow_dur, total_pkts, syn_count, rst_count]])

#3.5 agregam pachetele intr-o fereastra de 2 secunde
def agregare_pachete(pachet):
    features["dest_port"].append(pachet["dport"])
    features["flow_duration"].append(pachet["time"])
    features["total_fdw_packets"].append(1)  # fiecare pachet conteaza ca 1
    features["syn_flag_count"].append(1 if "S" in pachet["flags"] else 0)
    features["rst_flag_count"].append(1 if "R" in pachet["flags"] else 0)

#3.6 scalam features folosind scaler-ul incarcat apoi le dam modelului
def ruleaza_model(features):
    # transformam features intr-un array numpy
    X = np.array([[features["dest_port"][-1],
                   features["flow_duration"][-1] - features["flow_duration"][0],
                   sum(features["total_fdw_packets"]),
                   sum(features["syn_flag_count"]),
                   sum(features["rst_flag_count"])]])
    
    # scalare
    X_scaled = scaler.transform(X)
    
    # predictie
    predictie = model.predict(X_scaled)[0]
    score = model.decision_function(X_scaled)[0]
    
    return predictie, score



#3.8 daca e -1 atunci e anomalie, daca e 1 atunci e normal afisam rezultatul pe ecran
def afiseaza_verdict(predictie, score, features):
    ts = datetime.now().strftime("%H:%M:%S")
    if predictie == -1:
        print(f"\n{'='*55}")
        print(f"⚠  [{ts}] ANOMALIE DETECTATA! (score={score:.3f})")
        print(f"   Pachete: {sum(features['total_fdw_packets'])} | "
              f"SYN: {sum(features['syn_flag_count'])} | "
              f"RST: {sum(features['rst_flag_count'])}")
        print(f"   Features: dst_port={features['dest_port'][-1]}, "
              f"dur={features['flow_duration'][-1] - features['flow_duration'][0]:.0f}us, "
              f"pkts={sum(features['total_fdw_packets'])}, "
              f"SYN={sum(features['syn_flag_count'])}, "
              f"RST={sum(features['rst_flag_count'])}")
        print(f"{'='*55}\n")
    else:
        print(f"\n  ✓ [{ts}] Normal "
              f"({sum(features['total_fdw_packets'])} pachete, score={score:.3f})\n")


def reseteaza_fereastra():
    for key in features:
        features[key] = []   

def main():

    print("\n--- START NDR BACKEND ---")
    pachete_fereastra = []
    start   = time.time()
    total_anomalii    = 0
    total_ferestre    = 0

    try:
        while True:
            try:
                raw = port.readline().decode("utf-8", errors="ignore")
            except Exception:
                continue

            pachet = parsare_date(raw)
            if pachet:
                pachete_fereastra.append(pachet)
                agregare_pachete(pachet)

                # afisezi in timp real ce primesti
                print(f"  [{pachet['proto']:4s}] :{pachet['sport']:5d} -> :{pachet['dport']:5d}"
                      f"  flags={pachet['flags']:3s}  len={pachet['length']:4d}")

            # verifica daca a trecut fereastra de 2 secunde
            now = time.time()
            if now - start >= 2.0:
                total_ferestre += 1

                if pachete_fereastra:
                    predictie, score = ruleaza_model(features)
                    afiseaza_verdict(predictie, score, features)
                    if predictie == -1:
                        total_anomalii += 1 

                # reseteaza fereastra
                pachete_fereastra = []
                start = now
                reseteaza_fereastra()

    except KeyboardInterrupt:
        print(f"\n\n--- OPRIRE ---")
        print(f"Ferestre analizate: {total_ferestre}")
        print(f"Anomalii detectate: {total_anomalii}")
        port.close()



if __name__ == "__main__":
    main()        