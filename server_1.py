import os
import re
import time
import hashlib
import secrets

import requests
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

# ====== CONFIG ======
DB_URL = "https://ia-pdf-4aa9b-default-rtdb.firebaseio.com"
SERVICE_ACCOUNT = None   # à remplir seulement si tes règles Firebase sont restrictives
DUREE_SESSION = 7 * 24 * 3600   # 7 jours
# =====================

DOSSIER = os.path.dirname(os.path.abspath(__file__))
PROTEGES = ("users", "sessions")   # chemins interdits via /data
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = Flask(__name__)
_creds = None


# ---------- Firebase ----------
def _auth_params():
    global _creds
    if not SERVICE_ACCOUNT:
        return {}
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request
    if _creds is None:
        _creds = service_account.Credentials.from_service_account_info(
            SERVICE_ACCOUNT,
            scopes=["https://www.googleapis.com/auth/firebase.database",
                    "https://www.googleapis.com/auth/userinfo.email"],
        )
    if not _creds.valid:
        _creds.refresh(Request())
    return {"access_token": _creds.token}


def fb(methode, chemin, data=None):
    chemin = chemin.strip("/")
    url = f"{DB_URL}/{chemin}.json" if chemin else f"{DB_URL}/.json"
    r = requests.request(methode, url, params=_auth_params(), json=data, timeout=15)
    r.raise_for_status()
    return r.json()


# ---------- Outils ----------
def id_utilisateur(email):
    """Clé Firebase dérivée de l'e-mail (les clés ne peuvent pas contenir . # $ [ ] /)."""
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def erreur(message, code):
    return jsonify({"erreur": message}), code


def utilisateur_connecte():
    """Renvoie (id, utilisateur) à partir de l'en-tête Authorization: Bearer <token>."""
    entete = request.headers.get("Authorization", "")
    if not entete.startswith("Bearer "):
        return None, None
    token = entete[7:].strip()
    session = fb("GET", f"sessions/{hash_token(token)}")
    if not session or session.get("expire", 0) < time.time():
        return None, None
    user = fb("GET", f"users/{session['user_id']}")
    return session["user_id"], user


# ---------- Page d'accueil (interface de test) ----------
@app.get("/")
def accueil():
    return send_from_directory(DOSSIER, "index.html")


# ---------- Authentification ----------
@app.post("/inscription")
def inscription():
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip().lower()
    nom = str(d.get("nom", "")).strip()
    prenom = str(d.get("prenom", "")).strip()
    mdp = str(d.get("mot_de_passe", ""))

    if not (email and nom and prenom and mdp):
        return erreur("email, nom, prenom et mot_de_passe sont obligatoires", 400)
    if not EMAIL_RE.match(email):
        return erreur("adresse e-mail invalide", 400)
    if len(mdp) < 8:
        return erreur("le mot de passe doit contenir au moins 8 caractères", 400)

    uid = id_utilisateur(email)
    if fb("GET", f"users/{uid}") is not None:
        return erreur("un compte existe déjà avec cet e-mail", 409)

    fb("PUT", f"users/{uid}", {
        "email": email,
        "nom": nom,
        "prenom": prenom,
        "mot_de_passe_hash": generate_password_hash(mdp),
        "cree_le": int(time.time()),
    })
    return jsonify({"message": "inscription réussie"}), 201


@app.post("/connexion")
def connexion():
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip().lower()
    mdp = str(d.get("mot_de_passe", ""))

    uid = id_utilisateur(email)
    user = fb("GET", f"users/{uid}")
    # Même message dans les deux cas pour ne pas révéler si l'e-mail existe
    if not user or not check_password_hash(user["mot_de_passe_hash"], mdp):
        return erreur("e-mail ou mot de passe incorrect", 401)

    token = secrets.token_urlsafe(32)
    fb("PUT", f"sessions/{hash_token(token)}", {
        "user_id": uid,
        "expire": int(time.time()) + DUREE_SESSION,
    })
    return jsonify({
        "message": "connexion réussie",
        "token": token,
        "utilisateur": {"email": user["email"], "nom": user["nom"], "prenom": user["prenom"]},
    })


@app.get("/profil")
def profil():
    uid, user = utilisateur_connecte()
    if not user:
        return erreur("non connecté ou session expirée", 401)
    return jsonify({"email": user["email"], "nom": user["nom"], "prenom": user["prenom"]})


@app.post("/deconnexion")
def deconnexion():
    entete = request.headers.get("Authorization", "")
    if entete.startswith("Bearer "):
        fb("DELETE", f"sessions/{hash_token(entete[7:].strip())}")
    return jsonify({"message": "déconnecté"})


# ---------- Liste des comptes (test uniquement, sans les mots de passe) ----------
@app.get("/utilisateurs")
def liste_utilisateurs():
    users = fb("GET", "users") or {}
    liste = [
        {
            "email": u.get("email"),
            "nom": u.get("nom"),
            "prenom": u.get("prenom"),
            "cree_le": u.get("cree_le"),
        }
        for u in users.values()
    ]
    liste.sort(key=lambda u: u["cree_le"] or 0, reverse=True)
    return jsonify({"utilisateurs": liste})


# ---------- Routes génériques (users et sessions bloqués) ----------
def _bloque(chemin):
    premier = chemin.strip("/").split("/")[0]
    return premier in PROTEGES


@app.get("/data", defaults={"chemin": ""})
@app.get("/data/<path:chemin>")
def lire(chemin):
    if _bloque(chemin):
        return erreur("accès interdit", 403)
    data = fb("GET", chemin)
    if chemin.strip("/") == "" and isinstance(data, dict):
        data = {k: v for k, v in data.items() if k not in PROTEGES}
    return jsonify(data)


@app.post("/data/<path:chemin>")
def ajouter(chemin):
    if _bloque(chemin):
        return erreur("accès interdit", 403)
    return jsonify(fb("POST", chemin, request.get_json(force=True)))


@app.patch("/data/<path:chemin>")
def modifier(chemin):
    if _bloque(chemin):
        return erreur("accès interdit", 403)
    return jsonify(fb("PATCH", chemin, request.get_json(force=True)))


@app.errorhandler(requests.HTTPError)
def erreur_firebase(e):
    return erreur(f"erreur Firebase : {e.response.status_code}", 502)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
