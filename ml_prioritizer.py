"""
CTI Platform - ML Threat Prioritization Engine
Custom Random Forest — Python stdlib only, no sklearn needed!
Run: python ml_prioritizer.py  (run data_gen.py first)
"""

import json, random, math, os
from collections import Counter

random.seed(42)

# ── Decision Tree ────────────────────────────────────────────
class DecisionTree:
    def __init__(self, max_depth=6, min_samples=5):
        self.max_depth = max_depth
        self.min_samples = min_samples
        self.tree = None

    def fit(self, X, y):
        self.tree = self._build(X, y, 0)

    def _gini(self, y):
        n = len(y)
        if n == 0: return 0
        return 1 - sum((c/n)**2 for c in Counter(y).values())

    def _best_split(self, X, y):
        bg, bf, bt = float('inf'), None, None
        for f in range(len(X[0])):
            vals = sorted(set(r[f] for r in X))
            for t in [(vals[i]+vals[i+1])/2 for i in range(len(vals)-1)]:
                ly = [y[i] for i,r in enumerate(X) if r[f] <= t]
                ry = [y[i] for i,r in enumerate(X) if r[f] >  t]
                if not ly or not ry: continue
                g = (len(ly)*self._gini(ly) + len(ry)*self._gini(ry)) / len(y)
                if g < bg: bg, bf, bt = g, f, t
        return bf, bt

    def _build(self, X, y, d):
        if d >= self.max_depth or len(set(y)) == 1 or len(y) < self.min_samples:
            return {"leaf": True, "pred": Counter(y).most_common(1)[0][0]}
        f, t = self._best_split(X, y)
        if f is None:
            return {"leaf": True, "pred": Counter(y).most_common(1)[0][0]}
        m = [r[f] <= t for r in X]
        return {"leaf": False, "feat": f, "thresh": t,
                "left":  self._build([X[i] for i,v in enumerate(m) if v],
                                     [y[i] for i,v in enumerate(m) if v], d+1),
                "right": self._build([X[i] for i,v in enumerate(m) if not v],
                                     [y[i] for i,v in enumerate(m) if not v], d+1)}

    def predict_one(self, x):
        n = self.tree
        while not n["leaf"]:
            n = n["left"] if x[n["feat"]] <= n["thresh"] else n["right"]
        return n["pred"]

    def predict(self, X):
        return [self.predict_one(x) for x in X]


# ── Random Forest ────────────────────────────────────────────
class RandomForestClassifier:
    def __init__(self, n_trees=20, max_depth=6):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees = []
        self.fis = []

    def fit(self, X, y):
        n = len(X); nf = len(X[0])
        mf = max(1, int(math.sqrt(nf)))
        for _ in range(self.n_trees):
            idx = [random.randint(0, n-1) for _ in range(n)]
            fi  = sorted(random.sample(range(nf), min(mf, nf)))
            Xs  = [[X[i][f] for f in fi] for i in idx]
            ys  = [y[i] for i in idx]
            t   = DecisionTree(self.max_depth)
            t.fit(Xs, ys)
            self.trees.append(t); self.fis.append(fi)
        print(f"✅ Trained {self.n_trees} Decision Trees")

    def predict(self, X):
        ap = [t.predict([[r[f] for f in fi] for r in X])
              for t, fi in zip(self.trees, self.fis)]
        return [Counter([ap[t][i] for t in range(self.n_trees)]).most_common(1)[0][0]
                for i in range(len(X))]

    def predict_proba(self, X):
        ap = [t.predict([[r[f] for f in fi] for r in X])
              for t, fi in zip(self.trees, self.fis)]
        res = []
        for i in range(len(X)):
            v = [ap[t][i] for t in range(self.n_trees)]
            c = Counter(v)
            res.append({k: c[k]/self.n_trees for k in c})
        return res


# ── Feature Engineering ──────────────────────────────────────
SMAP  = {"CRITICAL":4, "HIGH":3, "MEDIUM":2, "LOW":1}
TMAP  = {t:i for i,t in enumerate(["Phishing","Ransomware","DDoS","APT","Malware",
         "Data Breach","Credential Stuffing","Supply Chain Attack","Zero-Day Exploit","Insider Threat"])}
STMAP = {"Active":3, "Investigating":2, "Monitoring":1, "Mitigated":0}

def features(t):
    return [
        t.get("risk_score", 50),
        SMAP.get(t.get("severity", "LOW"), 1),
        t.get("ioc_count", 0),
        t.get("confidence", 50),
        TMAP.get(t.get("threat_type", "Malware"), 0),
        STMAP.get(t.get("status", "Monitoring"), 1),
        1 if t.get("threat_actor","Unknown") != "Unknown" else 0,
        len(t.get("iocs",{}).get("ip_addresses",[])),
        len(t.get("iocs",{}).get("domains",[])),
        len(t.get("iocs",{}).get("hashes",[]))
    ]

def label(t):
    s   = t.get("risk_score", 50)
    sev = t.get("severity", "LOW")
    if sev == "CRITICAL" or s >= 85: return "P1_CRITICAL"
    elif sev == "HIGH"   or s >= 65: return "P2_HIGH"
    elif sev == "MEDIUM" or s >= 40: return "P3_MEDIUM"
    else:                            return "P4_LOW"

ACTIONS = {
    "P1_CRITICAL": "IMMEDIATE — Block all IOCs, escalate to SOC, start Incident Response",
    "P2_HIGH":     "URGENT — Investigate within 2 hours, apply mitigations",
    "P3_MEDIUM":   "MODERATE — Schedule review, monitor IOCs closely",
    "P4_LOW":      "ROUTINE — Log entry, monitor, review in next cycle"
}


# ── Threat Prioritizer ───────────────────────────────────────
class ThreatPrioritizer:
    def __init__(self):
        self.model   = RandomForestClassifier(n_trees=20, max_depth=6)
        self.trained = False

    def train(self, threats):
        X = [features(t) for t in threats]
        y = [label(t)    for t in threats]
        sp = int(0.8 * len(X))
        self.model.fit(X[:sp], y[:sp])
        self.trained = True
        preds = self.model.predict(X[sp:])
        acc   = sum(p==a for p,a in zip(preds, y[sp:])) / len(y[sp:])
        d     = Counter(y[:sp])
        print(f"✅ Accuracy : {acc*100:.1f}%")
        print(f"   P1:{d['P1_CRITICAL']}  P2:{d['P2_HIGH']}  P3:{d['P3_MEDIUM']}  P4:{d['P4_LOW']}")
        return acc

    def prioritize(self, threats):
        X     = [features(t) for t in threats]
        preds = self.model.predict(X)
        probs = self.model.predict_proba(X)
        results = []
        for t, p, pb in zip(threats, preds, probs):
            e = dict(t)
            e["ml_priority"]   = p
            e["ml_confidence"] = round(max(pb.values())*100, 1)
            e["action"]        = ACTIONS.get(p, "Review manually")
            results.append(e)
        order = {"P1_CRITICAL":0, "P2_HIGH":1, "P3_MEDIUM":2, "P4_LOW":3}
        results.sort(key=lambda x: order.get(x["ml_priority"], 4))
        return results


# ── Main ─────────────────────────────────────────────────────
if __name__ == "__main__":
    print("="*55)
    print("ML THREAT PRIORITIZATION — CTI PLATFORM")
    print("="*55)

    try:
        with open("data/threat_feed.json") as f:
            threats = json.load(f)
        print(f"✅ Loaded {len(threats)} threats from data/threat_feed.json")
    except FileNotFoundError:
        print("⚠  Run data_gen.py first!"); exit(1)

    p       = ThreatPrioritizer()
    p.train(threats)
    results = p.prioritize(threats)

    os.makedirs("data", exist_ok=True)
    with open("data/prioritized_threats.json","w") as f:
        json.dump(results, f, indent=2)

    print(f"\n🔍 Top 5 Critical Threats:")
    for t in results[:5]:
        print(f"  [{t['ml_priority']}] {t['threat_type']} | "
              f"Risk: {t['risk_score']} | Actor: {t['threat_actor']}")
        print(f"   → {t['action']}\n")

    print("✅ Saved → data/prioritized_threats.json")