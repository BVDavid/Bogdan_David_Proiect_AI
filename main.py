import pandas as pd
import numpy as np
import time
import sys
import random
import warnings
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

warnings.filterwarnings("ignore") # altfel apare UserWarning de la sklearn pt ca folosesc array in loc de DataFrame

# CONFIGURARE + INCARCARE DATE
def incarca_datele(cale_fisier):
    print(f"[INFO] Se încarcă datele din {cale_fisier}...")
    # Numele coloanelor cf, NSL-KDD documentation
    cols = ["duration","protocol_type","service","flag","src_bytes",
            "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
            "logged_in","num_compromised","root_shell","su_attempted","num_root",
            "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
            "is_host_login","is_guest_login","count","srv_count","serror_rate",
            "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
            "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
            "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
            "dst_host_rerror_rate","dst_host_srv_rerror_rate","class","difficulty"]

    try:
        df = pd.read_csv(cale_fisier, names=cols)
        # eliminare ultima coloana, pt ca nu e necesară (difficulty)
        df = df.drop('difficulty', axis=1)
        return df
    except FileNotFoundError:
        print("EROARE: Nu am găsit fișierul! Asigură-te că KDDTrain+.txt este în folder.")
        exit()

# PREPROCESARE (curatare) - convertire pachete de retea in caracterstici numerice (port,protcol,etc.)
def preprocesare_date(df):
    print("[INFO] Se procesează datele (transformare text -> numere)...")

    # Transformare eticheta (Target): 'normal' este 0, 'atac' este 1
    df['target'] = df['class'].apply(lambda x: 0 if x == 'normal' else 1)
    df = df.drop('class', axis=1) # stergere coloana veche text

    # Transformare coloanele text (protocol, service, flag) in numere
    cols_text = ['protocol_type', 'service', 'flag']
    encoder = LabelEncoder()

    for col in cols_text:
        df[col] = encoder.fit_transform(df[col])

    return df

# MODEL AI (antrenare)
def antrenare_si_evaluare(df):
    # separare datele (X) de rezultat (y)
    X = df.drop('target', axis=1)
    y = df['target']

    # impartire: 80% pt antrenare, 20% pt testare
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[INFO] Se antrenează modelul Random Forest (poate dura câteva secunde)...")
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)

    print("[INFO] Se evaluează modelul...")
    predictii = model.predict(X_test)

    # REZULTATE SI METRICI
    acc = accuracy_score(y_test, predictii)
    print("\n" + "="*40)
    print(f"REZULTATE FINALE")
    print("="*40)
    print(f"Acuratețe totală: {acc:.2%}") # Ex: 99.50%
    print("-" * 40)
    print("Raport Detaliat (Precision / Recall):")
    print(classification_report(y_test, predictii, target_names=['Normal', 'Atac']))

    # Matricea de confuzie simplified
    cm = confusion_matrix(y_test, predictii)
    print("-" * 40)
    print(f"Conexiuni Normale detectate corect: {cm[0][0]}")
    print(f"Atacuri detectate corect: {cm[1][1]}")
    print(f"Alarme False (Erori): {cm[0][1]}")
    print("="*40)

    # Returnam modelul si datele de test pentru a le folosi la VIZUALIZARE
    return model, X_test

def vizualizare_detectii_live(model, X_test):
    print("\n\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     🛡️  CYBERSECURITY AI DASHBOARD - LIVE MONITORING  🛡️    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("Se inițializează scanarea pachetelor în timp real...\n")
    time.sleep(2)

    # Luam 15 pachete random din setul de testare
    exemple_live = X_test.sample(15)

    for i, (index, row) in enumerate(exemple_live.iterrows()):
        # Pregatim datele pentru predictie
        date_pachet = row.values.reshape(1, -1)

        # Facem predictia si calculam increderea (%)
        predictie = model.predict(date_pachet)[0]
        probabilitate = model.predict_proba(date_pachet)[0] # returneaza [prob_normal, prob_atac]
        incredere = max(probabilitate) * 100

        # Generam un IP fictiv pentru aspect vizual
        ip_src = f"192.168.0.{random.randint(10, 200)}"

        # Afisare animata
        sys.stdout.write(f"[SCAN] IP: {ip_src} | Size: {row.iloc[4]} bytes | Analiză AI... ")
        sys.stdout.flush()
        time.sleep(0.6) # suspans

        if predictie == 1:
            # Daca e ATAC (rosu/alerta)
            print(f"⚠️  ATAC DETECTAT! (Încredere: {incredere:.2f}%)")
        else:
            # Daca e NORMAL (verde/ok)
            print(f"✅ TRAFIC NORMAL (Încredere: {incredere:.1f}%)")

        time.sleep(0.3)

    print("\n[INFO] Monitorizare încheiată. Sistemul este activ.")

# Main execution
if __name__ == "__main__":
    # Nume fisier descarcat
    fisier_date = "KDDTrain+.txt"

    # Apelare functii pe rand
    dataframe = incarca_datele(fisier_date)
    dataframe_procesat = preprocesare_date(dataframe)

    # preluam modelul antrenat
    model_antrenat, date_testare = antrenare_si_evaluare(dataframe_procesat)

    # Pornim vizualizarea
    vizualizare_detectii_live(model_antrenat, date_testare)