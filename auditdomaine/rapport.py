"""Sorties : rapport HTML autonome, résumé console, JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from html import escape

from .modeles import Categorie, Resultat, Statut

LIBELLES = {
    Statut.CRITIQUE: "Critique",
    Statut.ATTENTION: "À améliorer",
    Statut.OK: "Conforme",
    Statut.INFO: "Info",
}
ORDRE = {Statut.CRITIQUE: 0, Statut.ATTENTION: 1, Statut.INFO: 2, Statut.OK: 3}
COULEUR_NOTE = {"A": "ok", "B": "ok", "C": "attention", "D": "critique", "F": "critique"}
RESUME_NOTE = {
    "A": "Très bonne configuration. Quelques ajustements mineurs au plus.",
    "B": "Bonne base, avec quelques points à renforcer.",
    "C": "Protection partielle : plusieurs réglages importants manquent.",
    "D": "Exposition notable : des corrections sont recommandées rapidement.",
    "F": "Exposition élevée : des corrections prioritaires sont nécessaires.",
}

CSS = """
:root{--fond:#f6f7f9;--carte:#fff;--texte:#1d2330;--doux:#5d6677;--bord:#e3e6eb;
--ok:#1f7a4d;--ok-bg:#e3f4ea;--att:#9a5b00;--att-bg:#fdf0d9;--crit:#b3261e;--crit-bg:#fbe4e2;
--info:#2f5d9e;--info-bg:#e5edf8;--accent:#1f4e78}
@media (prefers-color-scheme:dark){:root{--fond:#14171c;--carte:#1c2027;--texte:#e7e9ee;--doux:#a0a8b6;
--bord:#2c323c;--ok:#6fd19b;--ok-bg:#16301f;--att:#f2b552;--att-bg:#33270f;--crit:#ff8a80;--crit-bg:#3a1a18;
--info:#8ab4f8;--info-bg:#18243a;--accent:#8ab4f8}}
*{box-sizing:border-box}
body{margin:0;background:var(--fond);color:var(--texte);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 48px}
header{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin-bottom:24px}
.note{width:96px;height:96px;border-radius:20px;display:grid;place-items:center;font-size:52px;font-weight:700;flex:none}
.note.ok{background:var(--ok-bg);color:var(--ok)}.note.attention{background:var(--att-bg);color:var(--att)}
.note.critique{background:var(--crit-bg);color:var(--crit)}
h1{margin:0;font-size:26px;word-break:break-all}
.sous{color:var(--doux);margin:2px 0 0}
.resume{margin:8px 0 0;font-weight:500}
.compteurs{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:0 0 28px}
.compteur{background:var(--carte);border:1px solid var(--bord);border-radius:12px;padding:12px;text-align:center}
.compteur b{display:block;font-size:24px}.compteur span{color:var(--doux);font-size:13px}
.c-critique b{color:var(--crit)}.c-attention b{color:var(--att)}.c-ok b{color:var(--ok)}.c-info b{color:var(--info)}
h2{font-size:18px;margin:32px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--bord)}
.item{background:var(--carte);border:1px solid var(--bord);border-left-width:4px;border-radius:10px;padding:14px 16px;margin-bottom:10px}
.item.critique{border-left-color:var(--crit)}.item.attention{border-left-color:var(--att)}
.item.ok{border-left-color:var(--ok)}.item.info{border-left-color:var(--info)}
.ligne{display:flex;justify-content:space-between;gap:12px;align-items:baseline;flex-wrap:wrap}
.titre{font-weight:600}
.pastille{font-size:12px;font-weight:600;padding:2px 10px;border-radius:99px;white-space:nowrap}
.pastille.critique{background:var(--crit-bg);color:var(--crit)}.pastille.attention{background:var(--att-bg);color:var(--att)}
.pastille.ok{background:var(--ok-bg);color:var(--ok)}.pastille.info{background:var(--info-bg);color:var(--info)}
.detail{margin:6px 0 0;color:var(--doux)}
.reco{margin:8px 0 0;padding:8px 12px;background:var(--fond);border-radius:8px;font-size:14px}
.reco::before{content:"→ ";font-weight:700;color:var(--accent)}
ol.prio{padding-left:22px}ol.prio li{margin-bottom:8px}
footer{margin-top:40px;color:var(--doux);font-size:13px;border-top:1px solid var(--bord);padding-top:16px}
@media (max-width:560px){.compteurs{grid-template-columns:repeat(2,1fr)}.note{width:76px;height:76px;font-size:40px}}
@media print{body{background:#fff}.item,.compteur{break-inside:avoid}}
"""


def _trier(constats):
    return sorted(constats, key=lambda c: ORDRE[c.statut])


def generer_html(r: Resultat, auteur: str = "") -> str:
    e = escape
    nb = {s: sum(1 for c in r.constats if c.statut == s) for s in Statut}

    compteurs = "".join(
        f'<div class="compteur c-{s.value}"><b>{nb[s]}</b><span>{LIBELLES[s]}</span></div>'
        for s in (Statut.CRITIQUE, Statut.ATTENTION, Statut.OK, Statut.INFO)
    )

    priorites = [c for c in _trier(r.constats) if c.statut in (Statut.CRITIQUE, Statut.ATTENTION) and c.recommandation]
    bloc_prio = ""
    if priorites:
        items = "".join(
            f'<li><b>{e(c.titre)}</b> <span class="pastille {c.statut.value}">{LIBELLES[c.statut]}</span><br>{e(c.recommandation)}</li>'
            for c in priorites
        )
        bloc_prio = f"<h2>Actions prioritaires</h2><ol class=\"prio\">{items}</ol>"

    sections = ""
    for cat in Categorie:
        liste = [c for c in r.constats if c.categorie == cat]
        if not liste:
            continue
        items = ""
        for c in _trier(liste):
            reco = f'<p class="reco">{e(c.recommandation)}</p>' if c.recommandation and c.statut != Statut.OK else ""
            items += (
                f'<div class="item {c.statut.value}"><div class="ligne"><span class="titre">{e(c.titre)}</span>'
                f'<span class="pastille {c.statut.value}">{LIBELLES[c.statut]}</span></div>'
                f'<p class="detail">{e(c.detail)}</p>{reco}</div>'
            )
        sections += f"<h2>{e(cat.value)}</h2>{items}"

    par = f" par {e(auteur)}" if auteur else ""
    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit de sécurité — {e(r.domaine)}</title><style>{CSS}</style></head>
<body><main>
<header><div class="note {COULEUR_NOTE[r.note]}">{r.note}</div>
<div><h1>{e(r.domaine)}</h1><p class="sous">Audit de sécurité passif · {r.date:%d/%m/%Y} · score {r.score}/100</p>
<p class="resume">{RESUME_NOTE[r.note]}</p></div></header>
<section class="compteurs">{compteurs}</section>
{bloc_prio}
{sections}
<footer>
<p><b>Méthode.</b> Audit passif réalisé{par} à partir d'informations publiques : enregistrements DNS, certificat
présenté par le serveur et en-têtes de la page d'accueil. Aucun test d'intrusion n'a été effectué.</p>
<p><b>Limites.</b> Cet audit ne couvre ni les applications du site, ni les postes de travail, ni les comptes
utilisateurs. Il donne un état des lieux de l'exposition visible depuis Internet à la date indiquée.</p>
</footer>
</main></body></html>
"""


def resume_console(r: Resultat) -> str:
    symboles = {Statut.CRITIQUE: "✗", Statut.ATTENTION: "!", Statut.OK: "✓", Statut.INFO: "i"}
    lignes = [f"\n  {r.domaine} — note {r.note} ({r.score}/100)", f"  {RESUME_NOTE[r.note]}\n"]
    for cat in Categorie:
        liste = [c for c in r.constats if c.categorie == cat]
        if liste:
            lignes.append(f"  {cat.value}")
            lignes += [f"    [{symboles[c.statut]}] {c.titre} — {c.detail}" for c in _trier(liste)]
            lignes.append("")
    return "\n".join(lignes)


def _jsonable(o):
    if isinstance(o, Enum):
        return o.value
    if hasattr(o, "isoformat"):
        return o.isoformat()
    raise TypeError(type(o))


def generer_json(r: Resultat) -> str:
    return json.dumps(asdict(r), default=_jsonable, ensure_ascii=False, indent=2)
