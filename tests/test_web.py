from datetime import datetime, timedelta, timezone

import pytest

from auditdomaine.modeles import InfoCertificat, InfoHTTP, Statut
from auditdomaine.web_checks import analyser_certificat, analyser_entetes, analyser_redirection

MAINTENANT = datetime(2026, 10, 8, tzinfo=timezone.utc)


def cert(jours, tls="TLSv1.3"):
    return InfoCertificat(valide=True, expire_le=MAINTENANT + timedelta(days=jours), emetteur="CA", version_tls=tls)


@pytest.mark.parametrize("jours, attendu", [(-1, Statut.CRITIQUE), (5, Statut.CRITIQUE), (20, Statut.ATTENTION), (90, Statut.OK)])
def test_expiration(jours, attendu):
    assert analyser_certificat(cert(jours), MAINTENANT)[0].statut == attendu


def test_certificat_absent_ou_invalide():
    assert analyser_certificat(None)[0].statut == Statut.CRITIQUE
    c = analyser_certificat(InfoCertificat(valide=False, erreur="hostname mismatch"))
    assert c[0].statut == Statut.CRITIQUE and "hostname mismatch" in c[0].detail


@pytest.mark.parametrize("tls, attendu", [("TLSv1", Statut.CRITIQUE), ("TLSv1.1", Statut.CRITIQUE), ("TLSv1.2", Statut.OK), ("TLSv1.3", Statut.OK)])
def test_version_tls(tls, attendu):
    c = analyser_certificat(cert(90, tls), MAINTENANT)
    assert next(x for x in c if x.titre == "Version du protocole TLS").statut == attendu


def test_redirection():
    assert analyser_redirection(InfoHTTP(True, http_redirige_vers_https=True))[0].statut == Statut.OK
    assert analyser_redirection(InfoHTTP(True, http_redirige_vers_https=False))[0].statut == Statut.ATTENTION
    assert analyser_redirection(InfoHTTP(True, http_redirige_vers_https=None))[0].statut == Statut.INFO


def par_titre(constats):
    return {c.titre: c.statut for c in constats}


def test_entetes_complets():
    r = par_titre(analyser_entetes({
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "Server": "nginx",
    }))
    assert all(s == Statut.OK for s in r.values()), r
    assert "Divulgation de versions logicielles" not in r


def test_entetes_absents():
    r = par_titre(analyser_entetes({}))
    for titre in ("HSTS", "Content-Security-Policy", "Protection anti-clickjacking", "X-Content-Type-Options"):
        assert r[titre] == Statut.ATTENTION
    assert r["Referrer-Policy"] == Statut.INFO and r["Permissions-Policy"] == Statut.INFO


def test_hsts_trop_court():
    assert par_titre(analyser_entetes({"Strict-Transport-Security": "max-age=300"}))["HSTS"] == Statut.ATTENTION


def test_csp_unsafe_inline():
    r = par_titre(analyser_entetes({"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"}))
    assert r["Content-Security-Policy"] == Statut.INFO


def test_xfo_suffit_contre_clickjacking():
    assert par_titre(analyser_entetes({"X-Frame-Options": "sameorigin"}))["Protection anti-clickjacking"] == Statut.OK


def test_divulgation_version():
    c = analyser_entetes({"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"})
    fuite = next(x for x in c if x.titre == "Divulgation de versions logicielles")
    assert "Apache/2.4.41" in fuite.detail and "PHP/7.4" in fuite.detail
