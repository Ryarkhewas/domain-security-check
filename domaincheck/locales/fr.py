"""French translation of the report.

Keys are the English texts (or templates, with their {placeholders}) used in
the code; tests/test_i18n.py checks that every one of them is translated here.
"""

FR: dict[str, str] = {
    # --- Categories, statuses, report labels -----------------------------------------
    "Website security": "Sécurité du site web",
    "Certificate & TLS": "Certificat & TLS",
    "Email protection": "Protection des emails",
    "Domain & DNS": "Domaine & DNS",
    "Website": "Site web",
    "Email": "Email",
    "Critical": "Critique",
    "To improve": "À améliorer",
    "Compliant": "Conforme",
    "Info": "Info",
    "Mozilla HTTP Observatory scoring": "barème Mozilla HTTP Observatory",
    "this project's scale (RFC 8996, 9325, certificate validity)": "barème du projet (RFC 8996, 9325, validité du certificat)",
    "this project's scale (RFC 7208, 7489, 6376, 8461)": "barème du projet (RFC 7208, 7489, 6376, 8461)",
    "this project's scale (RFC 4033, 8659, 9083, 9162)": "barème du projet (RFC 4033, 8659, 9083, 9162)",
    "Very good configuration. A few minor adjustments at most.":
        "Très bonne configuration. Au plus quelques ajustements mineurs.",
    "Solid foundation, with a few points to strengthen.": "Bonne base, avec quelques points à renforcer.",
    "Partial protection: several important settings are missing.":
        "Protection partielle : plusieurs réglages importants manquent.",
    "Significant exposure: fixes are recommended soon.": "Exposition importante : des corrections sont à prévoir rapidement.",
    "High exposure: priority fixes are needed.": "Exposition élevée : des corrections prioritaires sont nécessaires.",
    "No grade could be computed.": "Aucune note n'a pu être calculée.",
    "Security audit": "Audit de sécurité",
    "Passive security audit": "Audit de sécurité passif",
    "overall grade = weakest area": "note globale = domaine le plus faible",
    "overall grade {grade}": "note globale {grade}",
    "weakest area": "domaine le plus faible",
    "Overall": "Global",
    "Domain": "Domaine",
    "Priority actions": "Actions prioritaires",
    "Source:": "Source :",
    "See also:": "Voir aussi :",
    "not scored": "non noté",
    "{points} pts": "{points} pts",
    "Page {number}": "Page {number}",
    " by {author}": " par {author}",
    "{reason}: website grade capped at F.": "{reason} : la note du site est plafonnée à F.",
    "Method.": "Méthode.",
    "Grades.": "Notes.",
    "Limits.": "Limites.",
    "Passive audit carried out{by} using public information only: DNS records, the certificate presented by the "
    "server and the home page. No intrusion testing was performed.":
        "Audit passif réalisé{by} à partir d'informations publiques uniquement : enregistrements DNS, certificat "
        "présenté par le serveur et page d'accueil. Aucun test d'intrusion n'a été effectué.",
    "The website grade follows the {link} (penalties and bonuses per header). The certificate, email and DNS grades "
    "use this project's own scale, based on the standards cited under each item. The overall grade is the lowest of "
    "the four.":
        "La note du site web suit le {link} (pénalités et bonus par en-tête). Les notes certificat, email et "
        "DNS suivent le barème propre au projet, fondé sur les normes citées sous chaque point. La note globale est la "
        "plus basse des quatre.",
    "This audit does not cover the site's applications, workstations or user accounts. It gives an overview of the "
    "exposure visible from the Internet on the date shown. The ANSSI recommendations cited show what each check "
    "relates to; meeting them fully also depends on settings that cannot be seen from outside, so this report is not "
    "a certificate of compliance.":
        "Cet audit ne couvre pas les applications du site, les postes de travail ni les comptes utilisateurs. Il donne "
        "une vue d'ensemble de l'exposition visible depuis Internet à la date indiquée. Les recommandations de l'ANSSI "
        "citées indiquent à quoi se rattache chaque contrôle ; les respecter pleinement dépend aussi de réglages "
        "invisibles depuis l'extérieur : ce rapport n'est donc pas une attestation de conformité.",
    "Security audit of {count} domains": "Audit de sécurité de {count} domaines",
    "weakest domains first · click a domain for its full report":
        "domaines les plus faibles en premier · cliquez sur un domaine pour son rapport complet",
    "Not audited: {reason}": "Non audité : {reason}",
    "Passive audit carried out{by} using public information only. Each report explains its grades, the points behind "
    "them and the standard each check relies on.":
        "Audit passif réalisé{by} à partir d'informations publiques uniquement. Chaque rapport explique ses notes, les "
        "points qui les composent et la norme sur laquelle repose chaque contrôle.",
    # --- Grades ----------------------------------------------------------------------
    "No website answers on this domain.": "Aucun site web ne répond sur ce domaine.",
    "Capped at F: {reason}.": "Plafonnée à F : {reason}.",
    "DNSSEC and CAA could not be checked.": "DNSSEC et CAA n'ont pas pu être vérifiés.",
    "the site is reachable over HTTP but not over HTTPS": "le site répond en HTTP mais pas en HTTPS",
    "the HTTPS certificate is not valid ({error})": "le certificat HTTPS n'est pas valide ({error})",
    "the HTTPS certificate has expired": "le certificat HTTPS a expiré",
    "unknown error": "erreur inconnue",
    # --- Certificate & TLS -----------------------------------------------------------
    "HTTPS certificate": "Certificat HTTPS",
    "TLS protocol version": "Version du protocole TLS",
    "Accepted TLS versions": "Versions de TLS acceptées",
    "TLS 1.3": "TLS 1.3",
    "Weak cipher suites": "Suites de chiffrement faibles",
    "Forward secrecy": "Confidentialité persistante",
    "Certificate key": "Clé du certificat",
    "the server did not answer the test connections": "le serveur n'a pas répondu aux connexions de test",
    "The server still accepts SSL 3.0, broken since 2014 (POODLE attack). Accepted: {versions}.":
        "Le serveur accepte encore SSL 3.0, cassé depuis 2014 (attaque POODLE). Versions acceptées : {versions}.",
    "Disable SSL 3.0, TLS 1.0 and TLS 1.1 and only allow TLS 1.2 and 1.3.":
        "Désactivez SSL 3.0, TLS 1.0 et TLS 1.1 et n'autorisez que TLS 1.2 et 1.3.",
    "The server still accepts old versions ({old}), deprecated since 2021: an attacker who can force an old version weakens the "
    "encryption. Accepted: {versions}.":
        "Le serveur accepte encore d'anciennes versions ({old}), abandonnées depuis 2021 : un attaquant capable d'imposer une ancienne "
        "version affaiblit le chiffrement. Versions acceptées : {versions}.",
    "Disable TLS 1.0 and 1.1 and only allow TLS 1.2 and 1.3 (current browsers no longer use the old versions).":
        "Désactivez TLS 1.0 et 1.1 et n'autorisez que TLS 1.2 et 1.3 (les navigateurs actuels n'utilisent plus les "
        "anciennes versions).",
    "Only current versions are accepted: {versions}.": "Seules des versions actuelles sont acceptées : {versions}.",
    "Not supported: TLS 1.3 is faster and removes the weak options of older versions.":
        "Non pris en charge : TLS 1.3 est plus rapide et supprime les options faibles des versions précédentes.",
    "Enable TLS 1.3 in the server or hosting configuration, next to TLS 1.2.":
        "Activez TLS 1.3 dans la configuration du serveur ou de l'hébergement, en plus de TLS 1.2.",
    "The server accepts broken cipher suites (RC4, 3DES, export, no encryption or no authentication): {suites}.":
        "Le serveur accepte des suites de chiffrement cassées (RC4, 3DES, export, sans chiffrement ou sans "
        "authentification) : {suites}.",
    "Remove these suites from the server configuration and keep only AES-GCM and ChaCha20 suites with ECDHE.":
        "Retirez ces suites de la configuration du serveur et ne gardez que des suites AES-GCM et ChaCha20 avec ECDHE.",
    "No broken cipher suite accepted (RC4, 3DES, export, no encryption or no authentication).":
        "Aucune suite de chiffrement cassée acceptée (RC4, 3DES, export, sans chiffrement ou sans authentification).",
    "The suite chosen for a current browser ({suite}) has no forward secrecy: if the server's private key is stolen "
    "one day, recorded traffic can be decrypted.":
        "La suite choisie pour un navigateur actuel ({suite}) n'offre pas de confidentialité persistante : si la clé "
        "privée du serveur est volée un jour, le trafic enregistré pourra être déchiffré.",
    "Prefer ECDHE suites (and TLS 1.3) in the server configuration.":
        "Privilégiez les suites ECDHE (et TLS 1.3) dans la configuration du serveur.",
    "Current browsers get forward secrecy, but the server still accepts the RSA key exchange for old clients: their "
    "recorded traffic could be decrypted if the private key is stolen.":
        "Les navigateurs actuels bénéficient de la confidentialité persistante, mais le serveur accepte encore "
        "l'échange de clés RSA pour les anciens clients : leur trafic enregistré pourrait être déchiffré si la clé "
        "privée était volée.",
    "Remove the suites without ECDHE or DHE (AES128-SHA, AES256-GCM-SHA384...).":
        "Retirez les suites sans ECDHE ni DHE (AES128-SHA, AES256-GCM-SHA384...).",
    "Every accepted key exchange has forward secrecy: a stolen private key would not decrypt recorded traffic.":
        "Tous les échanges de clés acceptés offrent la confidentialité persistante : une clé privée volée ne "
        "permettrait pas de déchiffrer le trafic enregistré.",
    "{kind} {bits} bits": "{kind} {bits} bits",
    "Key too short ({key}): it could be broken.": "Clé trop courte ({key}) : elle pourrait être cassée.",
    "Issue a new certificate with an RSA key of at least 2048 bits or an ECDSA P-256 key.":
        "Faites émettre un nouveau certificat avec une clé RSA d'au moins 2048 bits ou une clé ECDSA P-256.",
    "Key strong enough ({key}).": "Clé suffisamment robuste ({key}).",
    "Could not establish an HTTPS connection on port 443.": "Impossible d'établir une connexion HTTPS sur le port 443.",
    "Install a certificate (Let's Encrypt is free) and enable HTTPS.":
        "Installez un certificat (Let's Encrypt est gratuit) et activez le HTTPS.",
    "The certificate is not recognised as valid: {error}. Browsers show a warning to visitors.":
        "Le certificat n'est pas reconnu comme valide : {error}. Les navigateurs affichent un avertissement aux "
        "visiteurs.",
    "Replace it with a valid certificate covering this domain name.":
        "Remplacez-le par un certificat valide qui couvre ce nom de domaine.",
    "Certificate expired on {date}.": "Certificat expiré depuis le {date}.",
    "Renew the certificate immediately.": "Renouvelez le certificat immédiatement.",
    "The certificate expires in {days} day(s) ({date}).": "Le certificat expire dans {days} jour(s) ({date}).",
    "Renew it now and set up automatic renewal.": "Renouvelez-le maintenant et mettez en place le renouvellement automatique.",
    "The certificate expires in {days} days ({date}).": "Le certificat expire dans {days} jours ({date}).",
    "Check that automatic renewal is in place.": "Vérifiez que le renouvellement automatique est en place.",
    ", issued by {issuer}": ", émis par {issuer}",
    "Certificate valid until {date} ({days} days){issuer}.": "Certificat valide jusqu'au {date} ({days} jours){issuer}.",
    "Connection negotiated with {version}, an obsolete and vulnerable version.":
        "Connexion établie en {version}, une version obsolète et vulnérable.",
    "Disable TLS 1.0/1.1 on the server and only allow TLS 1.2 and 1.3.":
        "Désactivez TLS 1.0/1.1 sur le serveur et n'autorisez que TLS 1.2 et 1.3.",
    "Connection negotiated with {version}.": "Connexion établie en {version}.",
    # --- Website: redirection, HSTS --------------------------------------------------
    "HTTP to HTTPS redirect": "Redirection HTTP vers HTTPS",
    "An invalid certificate was encountered while following the redirects.":
        "Un certificat non valide a été rencontré en suivant les redirections.",
    "Fix the certificate of every host involved in the redirects.":
        "Corrigez le certificat de chaque serveur impliqué dans les redirections.",
    "The site does not answer on plain HTTP (port 80). No redirect needed.":
        "Le site ne répond pas en HTTP simple (port 80). Aucune redirection n'est nécessaire.",
    "Every host involved is in the browsers' HSTS preload list: browsers never use HTTP for them, whatever the "
    "redirects.":
        "Tous les serveurs concernés sont dans la liste HSTS préchargée des navigateurs : ceux-ci n'utilisent jamais "
        "HTTP pour eux, quelles que soient les redirections.",
    "The site is still reachable over unencrypted HTTP, without a redirect.":
        "Le site reste accessible en HTTP non chiffré, sans redirection.",
    "Set up a permanent (301) redirect from HTTP to HTTPS.": "Mettez en place une redirection permanente (301) de HTTP vers HTTPS.",
    "The site redirects, but the final page is not served over HTTPS.":
        "Le site redirige, mais la page finale n'est pas servie en HTTPS.",
    "Make the redirects end on an HTTPS address.": "Faites aboutir les redirections sur une adresse HTTPS.",
    "The site ends on HTTPS, but the first redirect goes to another HTTP address.":
        "Le site finit en HTTPS, mais la première redirection mène vers une autre adresse HTTP.",
    "Redirect http://{host} directly to https://{host} first, so that HSTS can apply.":
        "Redirigez d'abord http://{host} directement vers https://{host}, pour que HSTS puisse s'appliquer.",
    "The first redirect goes to a different host ({other}), which prevents HSTS on {host}.":
        "La première redirection mène vers un autre serveur ({other}), ce qui empêche HSTS sur {host}.",
    "Redirect http://{host} to https://{host} first, then to the other host.":
        "Redirigez d'abord http://{host} vers https://{host}, puis vers l'autre serveur.",
    "Visitors arriving over HTTP are redirected to HTTPS.": "Les visiteurs arrivant en HTTP sont redirigés vers HTTPS.",
    "HSTS": "HSTS",
    "In the browsers' HSTS preload list: HTTPS is enforced even on the first visit.":
        "Dans la liste HSTS préchargée des navigateurs : le HTTPS est imposé dès la première visite.",
    "Missing: the browser is not required to use HTTPS on later visits.":
        "Absent : le navigateur n'est pas obligé d'utiliser HTTPS lors des visites suivantes.",
    'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".':
        'Ajoutez « Strict-Transport-Security: max-age=31536000; includeSubDomains ».',
    'The header cannot be understood: "{value}".': "L'en-tête est incompréhensible : « {value} ».",
    'Use the form "max-age=31536000; includeSubDomains".': "Utilisez la forme « max-age=31536000; includeSubDomains ».",
    "Present but short duration (max-age={age}).": "Présent, mais durée courte (max-age={age}).",
    "Use at least 6 months (max-age=15552000), ideally 1 year.":
        "Utilisez au moins 6 mois (max-age=15552000), idéalement 1 an.",
    "Present (max-age={age}).": "Présent (max-age={age}).",
    # --- Website: CSP ----------------------------------------------------------------
    "Content-Security-Policy": "Content-Security-Policy",
    "Only a test policy exists (Content-Security-Policy-Report-Only): violations are reported, but nothing is "
    "blocked.":
        "Seule une politique de test existe (Content-Security-Policy-Report-Only) : les violations sont signalées, "
        "mais rien n'est bloqué.",
    "Once the reports are clean, enforce the policy with the Content-Security-Policy header.":
        "Une fois les rapports propres, appliquez la politique avec l'en-tête Content-Security-Policy.",
    "Missing: no limit on which scripts the page can load (protection against XSS injection).":
        "Absent : aucune limite sur les scripts que la page peut charger (protection contre les injections XSS).",
    'Define a CSP suited to the site, starting in "Report-Only" mode.':
        "Définissez une CSP adaptée au site, en commençant en mode « Report-Only ».",
    "The policy cannot be parsed ({error}).": "La politique est illisible ({error}).",
    "Check the syntax, for instance with Google's CSP Evaluator.":
        "Vérifiez la syntaxe, par exemple avec le CSP Evaluator de Google.",
    "'strict-dynamic' is used without a nonce or hash, which makes the policy invalid.":
        "'strict-dynamic' est utilisé sans nonce ni hash, ce qui rend la politique invalide.",
    "Add a nonce or hash to script-src, or remove 'strict-dynamic'.":
        "Ajoutez un nonce ou un hash à script-src, ou retirez 'strict-dynamic'.",
    "Present, but unsafe: script-src allows 'unsafe-inline', data: or overly broad sources, or script-src / "
    "object-src are not restricted.":
        "Présente, mais peu sûre : script-src autorise 'unsafe-inline', data: ou des sources trop larges, ou "
        "script-src / object-src ne sont pas restreints.",
    "Remove 'unsafe-inline' and data: from script-src, avoid broad sources such as https:, and set object-src and "
    "script-src.":
        "Retirez 'unsafe-inline' et data: de script-src, évitez les sources larges comme https:, et définissez "
        "object-src et script-src.",
    "Present, but allows scripts or other active content to be loaded over plain HTTP.":
        "Présente, mais autorise le chargement de scripts ou d'autres contenus actifs en HTTP simple.",
    "Load every resource over HTTPS and remove http: sources from the policy.":
        "Chargez toutes les ressources en HTTPS et retirez les sources http: de la politique.",
    "Present, but allows 'unsafe-eval'.": "Présente, mais autorise 'unsafe-eval'.",
    "Remove the use of eval() from the code, then remove 'unsafe-eval' from the policy.":
        "Supprimez l'usage d'eval() dans le code, puis retirez 'unsafe-eval' de la politique.",
    "Present, but allows images or media to be loaded over plain HTTP.":
        "Présente, mais autorise le chargement d'images ou de médias en HTTP simple.",
    "Load images and media over HTTPS only.": "Chargez les images et les médias uniquement en HTTPS.",
    "Present; only style-src allows unsafe sources such as 'unsafe-inline'.":
        "Présente ; seul style-src autorise des sources peu sûres comme 'unsafe-inline'.",
    "Lock down style-src by removing 'unsafe-inline', data: and broad sources.":
        "Restreignez style-src en retirant 'unsafe-inline', data: et les sources larges.",
    "Present and strict (default-src 'none', no unsafe sources).":
        "Présente et stricte (default-src 'none', aucune source peu sûre).",
    "Present, without 'unsafe-inline' or 'unsafe-eval'.": "Présente, sans 'unsafe-inline' ni 'unsafe-eval'.",
    "For the maximum score, set default-src to 'none' and allow each resource type explicitly.":
        "Pour le score maximal, mettez default-src à 'none' et autorisez explicitement chaque type de ressource.",
    # --- Website: other headers ------------------------------------------------------
    "Clickjacking protection": "Protection contre le clickjacking",
    "Protected by the CSP frame-ancestors directive.": "Protégé par la directive CSP frame-ancestors.",
    "The site can be displayed inside a frame on another site (clickjacking risk).":
        "Le site peut être affiché dans un cadre sur un autre site (risque de clickjacking).",
    "Add \"X-Frame-Options: SAMEORIGIN\" or \"frame-ancestors 'self'\" in the CSP.":
        "Ajoutez « X-Frame-Options: SAMEORIGIN » ou « frame-ancestors 'self' » dans la CSP.",
    "X-Frame-Options set to {value}.": "X-Frame-Options réglé sur {value}.",
    "X-Frame-Options uses ALLOW-FROM, which modern browsers ignore.":
        "X-Frame-Options utilise ALLOW-FROM, que les navigateurs récents ignorent.",
    "Use the CSP frame-ancestors directive instead.": "Utilisez plutôt la directive CSP frame-ancestors.",
    'X-Frame-Options cannot be understood: "{value}".': "X-Frame-Options est incompréhensible : « {value} ».",
    'Use "X-Frame-Options: SAMEORIGIN" or DENY.': "Utilisez « X-Frame-Options: SAMEORIGIN » ou DENY.",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Missing: the browser may misinterpret the type of some files.":
        "Absent : le navigateur peut se tromper sur le type de certains fichiers.",
    'Add "X-Content-Type-Options: nosniff".': "Ajoutez « X-Content-Type-Options: nosniff ».",
    "Present (nosniff).": "Présent (nosniff).",
    'Invalid value: "{value}".': "Valeur invalide : « {value} ».",
    'The only valid value is "nosniff".': "La seule valeur valide est « nosniff ».",
    "Referrer-Policy": "Referrer-Policy",
    "Missing: browsers apply their default policy (strict-origin-when-cross-origin in recent versions).":
        "Absent : les navigateurs appliquent leur politique par défaut (strict-origin-when-cross-origin dans les "
        "versions récentes).",
    'Add "Referrer-Policy: strict-origin-when-cross-origin" (worth bonus points).':
        "Ajoutez « Referrer-Policy: strict-origin-when-cross-origin » (rapporte des points bonus).",
    'Value not recognised: "{value}".': "Valeur non reconnue : « {value} ».",
    'Use "strict-origin-when-cross-origin".': "Utilisez « strict-origin-when-cross-origin ».",
    " in a <meta> tag of the page": " dans une balise <meta> de la page",
    "Present ({value}{where}).": "Présent ({value}{where}).",
    'Set to "{value}"{where}, which can leak page addresses to other sites.':
        "Réglé sur « {value} »{where}, ce qui peut transmettre les adresses des pages à d'autres sites.",
    "Not set (optional; earns bonus points when set).": "Non défini (facultatif ; rapporte des points bonus s'il est défini).",
    'Set to "{value}", which keeps the default, permissive behaviour.':
        "Réglé sur « {value} », qui garde le comportement par défaut, permissif.",
    "Cross-Origin-Resource-Policy": "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy": "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy": "Cross-Origin-Embedder-Policy",
    "Set to same-origin: resources cannot leak into other origins.":
        "Réglé sur same-origin : les ressources ne peuvent pas fuiter vers d'autres origines.",
    "Set to same-site: resources cannot leak into other sites.":
        "Réglé sur same-site : les ressources ne peuvent pas fuiter vers d'autres sites.",
    "Set to same-origin: the page is isolated from the windows that open it.":
        "Réglé sur same-origin : la page est isolée des fenêtres qui l'ouvrent.",
    "Set to same-origin-allow-popups: the page is isolated from its opener.":
        "Réglé sur same-origin-allow-popups : la page est isolée de la fenêtre qui l'ouvre.",
    "Set to noopener-allow-popups: the page is isolated from its opener.":
        "Réglé sur noopener-allow-popups : la page est isolée de la fenêtre qui l'ouvre.",
    "Set to require-corp: only explicitly allowed cross-origin resources load.":
        "Réglé sur require-corp : seules les ressources externes explicitement autorisées se chargent.",
    "Set to credentialless: cross-origin resources load without credentials.":
        "Réglé sur credentialless : les ressources externes se chargent sans identifiants.",
    # --- Website: cookies ------------------------------------------------------------
    "Cookies": "Cookies",
    "No cookies set on the home page.": "Aucun cookie déposé sur la page d'accueil.",
    "All cookies use the Secure flag, session cookies use HttpOnly, and SameSite is set.":
        "Tous les cookies ont l'attribut Secure, les cookies de session ont HttpOnly, et SameSite est défini.",
    "All cookies use the Secure flag and session cookies use HttpOnly, but some cookies have no SameSite flag.":
        "Tous les cookies ont l'attribut Secure et les cookies de session ont HttpOnly, mais certains cookies n'ont "
        "pas d'attribut SameSite.",
    "Some cookies lack the Secure flag, but HSTS prevents sending them over HTTP.":
        "Certains cookies n'ont pas l'attribut Secure, mais HSTS empêche de les envoyer en HTTP.",
    "A session cookie lacks the Secure flag, but HSTS prevents sending it over HTTP.":
        "Un cookie de session n'a pas l'attribut Secure, mais HSTS empêche de l'envoyer en HTTP.",
    "Some cookies lack the Secure flag and can be sent over unencrypted HTTP.":
        "Certains cookies n'ont pas l'attribut Secure et peuvent être envoyés en HTTP non chiffré.",
    "A cookie uses SameSite=None without the Secure flag.": "Un cookie utilise SameSite=None sans l'attribut Secure.",
    "An anti-CSRF cookie is set without the SameSite flag.": "Un cookie anti-CSRF est déposé sans l'attribut SameSite.",
    "A session cookie lacks the HttpOnly flag: JavaScript (and XSS attacks) can read it.":
        "Un cookie de session n'a pas l'attribut HttpOnly : JavaScript (et donc les attaques XSS) peut le lire.",
    "A session cookie lacks the Secure flag and can be sent over unencrypted HTTP.":
        "Un cookie de session n'a pas l'attribut Secure et peut être envoyé en HTTP non chiffré.",
    "{detail} (cookies: {names})": "{detail} (cookies : {names})",
    "Set Secure on every cookie, HttpOnly on session cookies, and SameSite=Lax or Strict.":
        "Mettez Secure sur chaque cookie, HttpOnly sur les cookies de session, et SameSite=Lax ou Strict.",
    # --- Website: Subresource Integrity ----------------------------------------------
    "Subresource Integrity": "Subresource Integrity (intégrité des scripts)",
    "The home page is not HTML: no scripts to check.": "La page d'accueil n'est pas du HTML : aucun script à vérifier.",
    "The home page claims to be HTML but cannot be parsed.":
        "La page d'accueil se dit en HTML mais ne peut pas être analysée.",
    "No scripts on the home page.": "Aucun script sur la page d'accueil.",
    "All scripts are loaded from the site's own domain (Subresource Integrity not needed).":
        "Tous les scripts sont chargés depuis le domaine du site (Subresource Integrity inutile).",
    "Subresource Integrity is used and all scripts are loaded from the site's own domain.":
        "Subresource Integrity est utilisé et tous les scripts sont chargés depuis le domaine du site.",
    "Subresource Integrity is used and all external scripts are loaded securely.":
        "Subresource Integrity est utilisé et tous les scripts externes sont chargés de façon sûre.",
    "Subresource Integrity is used, but some external scripts are loaded over HTTP or a protocol-relative URL "
    "(//...).":
        "Subresource Integrity est utilisé, mais certains scripts externes sont chargés en HTTP ou via une adresse "
        "sans protocole (//...).",
    "External scripts are loaded over HTTPS, but without Subresource Integrity: if the other site is compromised, "
    "its scripts run on this page.":
        "Des scripts externes sont chargés en HTTPS, mais sans Subresource Integrity : si l'autre site est piraté, "
        "ses scripts s'exécutent sur cette page.",
    "External scripts are loaded over HTTP or a protocol-relative URL (//...), without Subresource Integrity: they "
    "can be modified in transit.":
        "Des scripts externes sont chargés en HTTP ou via une adresse sans protocole (//...), sans Subresource "
        "Integrity : ils peuvent être modifiés en chemin.",
    "{detail} External scripts: {scripts}.": "{detail} Scripts externes : {scripts}.",
    'Load external scripts over HTTPS and add an integrity attribute (with crossorigin="anonymous") to each of them.':
        "Chargez les scripts externes en HTTPS et ajoutez un attribut integrity (avec crossorigin=\"anonymous\") à "
        "chacun.",
    # --- Website: not scored ---------------------------------------------------------
    "Permissions-Policy": "Permissions-Policy",
    "Present.": "Présent.",
    "Missing: no restriction on access to browser features (camera, microphone, geolocation).":
        "Absent : aucune restriction d'accès aux fonctions du navigateur (caméra, micro, géolocalisation).",
    'Add for example "Permissions-Policy: camera=(), microphone=(), geolocation=()".':
        "Ajoutez par exemple « Permissions-Policy: camera=(), microphone=(), geolocation=() ».",
    "Software version disclosure": "Versions des logiciels affichées",
    "The server announces its versions ({versions}), which helps an attacker target known vulnerabilities.":
        "Le serveur annonce ses versions ({versions}), ce qui aide un attaquant à cibler des failles connues.",
    "Hide version numbers in the server configuration.": "Masquez les numéros de version dans la configuration du serveur.",
    # --- Email -----------------------------------------------------------------------
    "Mail servers (MX)": "Serveurs de mail (MX)",
    "No MX server: this domain does not receive email.": "Aucun serveur MX : ce domaine ne reçoit pas d'email.",
    'If the domain does not send email either, publish "v=spf1 -all", a DMARC policy "p=reject" and a null MX record, '
    "so nobody can use it to impersonate you.":
        "Si le domaine n'envoie pas d'email non plus, publiez « v=spf1 -all », une politique DMARC « p=reject » et un "
        "enregistrement MX nul, pour que personne ne puisse l'utiliser pour se faire passer pour vous.",
    "{count} server(s): {names}": "{count} serveur(s) : {names}",
    "SPF (authorized senders)": "SPF (expéditeurs autorisés)",
    "No SPF record. Spoofed emails are still stopped by the domain's strict DMARC policy, but legitimate mail is "
    "more likely to be treated as spam.":
        "Aucun enregistrement SPF. Les emails usurpés restent bloqués par la politique DMARC stricte du domaine, mais "
        "vos emails légitimes risquent davantage d'être classés en spam.",
    'Publish an SPF record listing your sending services, or "v=spf1 -all" if this domain sends no email.':
        "Publiez un enregistrement SPF listant vos services d'envoi, ou « v=spf1 -all » si ce domaine n'envoie aucun "
        "email.",
    "No SPF record: anyone can send email pretending to be this domain.":
        "Aucun enregistrement SPF : n'importe qui peut envoyer des emails en se faisant passer pour ce domaine.",
    'Publish an SPF TXT record listing your sending services (e.g. "v=spf1 include:_spf.google.com -all").':
        "Publiez un enregistrement TXT SPF listant vos services d'envoi (par exemple "
        "« v=spf1 include:_spf.google.com -all »).",
    "{count} SPF records found: this is invalid, receiving servers ignore all of them.":
        "{count} enregistrements SPF trouvés : c'est invalide, les serveurs destinataires les ignorent tous.",
    "Merge them into a single SPF record.": "Fusionnez-les en un seul enregistrement SPF.",
    'The SPF record does not end with an "all" rule: "{record}".':
        "L'enregistrement SPF ne se termine pas par une règle « all » : « {record} ».",
    'End the record with "-all" (or "~all" during a test phase).':
        "Terminez l'enregistrement par « -all » (ou « ~all » pendant une phase de test).",
    'The SPF record ends with "+all": it allows the whole world to send on your behalf.':
        "L'enregistrement SPF se termine par « +all » : il autorise le monde entier à envoyer en votre nom.",
    'Replace "+all" with "-all".': "Remplacez « +all » par « -all ».",
    'The SPF record ends with "?all" (neutral): it provides almost no protection.':
        "L'enregistrement SPF se termine par « ?all » (neutre) : il ne protège presque pas.",
    'Move to "~all", then "-all" once your senders are listed.':
        "Passez à « ~all », puis à « -all » une fois vos expéditeurs listés.",
    'SPF present with "~all" (soft fail). Fine, especially combined with DMARC.':
        "SPF présent avec « ~all » (échec souple). Correct, surtout combiné à DMARC.",
    'Once you are sure of your list of senders, switch to "-all".':
        "Une fois sûr de votre liste d'expéditeurs, passez à « -all ».",
    'SPF present and strict ("-all").': "SPF présent et strict (« -all »).",
    "SPF: number of DNS lookups": "SPF : nombre de requêtes DNS",
    "{count} mechanisms require a DNS lookup (limit: 10). The SPF record may be rejected.":
        "{count} mécanismes nécessitent une requête DNS (limite : 10). L'enregistrement SPF peut être rejeté.",
    'Reduce the number of "include" entries or use an SPF flattening service.':
        "Réduisez le nombre d'« include » ou utilisez un service d'aplatissement SPF.",
    "DMARC (anti-spoofing policy)": "DMARC (politique anti-usurpation)",
    "No DMARC policy: fraudulent messages using your domain are neither blocked nor reported.":
        "Aucune politique DMARC : les messages frauduleux utilisant votre domaine ne sont ni bloqués ni signalés.",
    'Publish a TXT record on _dmarc.<domain>, starting with "v=DMARC1; p=none; rua=mailto:dmarc@<domain>" to '
    "monitor, then tighten it.":
        "Publiez un enregistrement TXT sur _dmarc.<domaine>, en commençant par "
        "« v=DMARC1; p=none; rua=mailto:dmarc@<domaine> » pour observer, puis durcissez-le.",
    "Several DMARC records: this is invalid, they are ignored.":
        "Plusieurs enregistrements DMARC : c'est invalide, ils sont ignorés.",
    "Keep a single DMARC record.": "Gardez un seul enregistrement DMARC.",
    "Inherited from {parent}: ": "Hérité de {parent} : ",
    '{origin}"reject" policy: spoofed emails are rejected.': "{origin}politique « reject » : les emails usurpés sont rejetés.",
    '{origin}"quarantine" policy: spoofed emails go to spam.':
        "{origin}politique « quarantine » : les emails usurpés vont en spam.",
    'Move to "reject" once the reports confirm your legitimate email passes.':
        "Passez à « reject » quand les rapports confirment que vos emails légitimes passent.",
    '{origin}"none" policy: DMARC monitors but blocks nothing.':
        "{origin}politique « none » : DMARC observe mais ne bloque rien.",
    'After a few weeks of report analysis, move to "quarantine", then "reject".':
        "Après quelques semaines d'analyse des rapports, passez à « quarantine », puis à « reject ».",
    "{origin}Missing or invalid DMARC policy ({tag}={policy}).":
        "{origin}politique DMARC absente ou invalide ({tag}={policy}).",
    "Fix the record: the {tag}= tag must be none, quarantine or reject.":
        "Corrigez l'enregistrement : la balise {tag}= doit valoir none, quarantine ou reject.",
    "DMARC: coverage": "DMARC : couverture",
    "The policy only applies to {pct}% of messages.": "La politique ne s'applique qu'à {pct} % des messages.",
    "Gradually raise it to pct=100.": "Augmentez-la progressivement jusqu'à pct=100.",
    "DMARC: reports": "DMARC : rapports",
    "No report address (rua): you cannot see who sends email on your behalf.":
        "Aucune adresse de rapport (rua) : vous ne voyez pas qui envoie des emails en votre nom.",
    'Add "rua=mailto:..." to receive aggregate reports.': "Ajoutez « rua=mailto:... » pour recevoir les rapports agrégés.",
    "DKIM (email signing)": "DKIM (signature des emails)",
    "DKIM key(s) found: {selectors}.": "Clé(s) DKIM trouvée(s) : {selectors}.",
    "No DKIM key found among the common selectors tested ({count}). This is not necessarily a problem: the selector "
    "may have another name.":
        "Aucune clé DKIM trouvée parmi les sélecteurs courants testés ({count}). Ce n'est pas forcément un problème : "
        "le sélecteur peut avoir un autre nom.",
    "Check in your email service (Google Workspace, Microsoft 365...) that DKIM signing is enabled.":
        "Vérifiez dans votre service de messagerie (Google Workspace, Microsoft 365…) que la signature DKIM est "
        "activée.",
    "MTA-STS (encrypted email delivery)": "MTA-STS (livraison chiffrée des emails)",
    "Not set: other mail servers may deliver your incoming email without encryption if an attacker tampers with the "
    "connection.":
        "Non défini : les autres serveurs de mail peuvent vous livrer vos emails sans chiffrement si un attaquant "
        "perturbe la connexion.",
    'Publish an MTA-STS policy (in "testing" mode first), or enable it in your email service.':
        "Publiez une politique MTA-STS (d'abord en mode « testing »), ou activez-la dans votre service de messagerie.",
    "The _mta-sts TXT record is invalid: {records}.": "L'enregistrement TXT _mta-sts est invalide : {records}.",
    'Publish a single record of the form "v=STSv1; id=20260101".':
        "Publiez un seul enregistrement de la forme « v=STSv1; id=20260101 ».",
    "Announced, but the policy file cannot be read ({error}): sending servers ignore it.":
        "Annoncé, mais le fichier de politique est illisible ({error}) : les serveurs expéditeurs l'ignorent.",
    "Serve the policy at https://mta-sts.<your-domain>/.well-known/mta-sts.txt (valid HTTPS, no redirect).":
        "Publiez la politique à l'adresse https://mta-sts.<votre-domaine>/.well-known/mta-sts.txt (HTTPS valide, sans "
        "redirection).",
    "version is not STSv1": "la version n'est pas STSv1",
    'unknown mode "{mode}"': "mode inconnu « {mode} »",
    "max_age missing or invalid": "max_age absent ou invalide",
    "no mx line": "aucune ligne mx",
    "The policy file is invalid: {problems}.": "Le fichier de politique est invalide : {problems}.",
    "Fix the policy file (fields: version, mode, mx, max_age).":
        "Corrigez le fichier de politique (champs : version, mode, mx, max_age).",
    'Policy in "none" mode: MTA-STS is switched off.': "Politique en mode « none » : MTA-STS est désactivé.",
    'Move to "testing", then "enforce".': "Passez à « testing », puis à « enforce ».",
    'Policy in "enforce" mode, but some mail servers are not listed ({servers}): servers applying MTA-STS will '
    "refuse to deliver email to them.":
        "Politique en mode « enforce », mais certains serveurs de mail ne sont pas listés ({servers}) : les serveurs "
        "qui appliquent MTA-STS refuseront de leur livrer des emails.",
    "Add these servers to the mx lines of the policy, then change its id.":
        "Ajoutez ces serveurs aux lignes mx de la politique, puis changez son id.",
    " Not listed: {servers}.": " Non listés : {servers}.",
    'Policy in "testing" mode: problems are reported but delivery is not yet protected.{extra}':
        "Politique en mode « testing » : les problèmes sont signalés mais la livraison n'est pas encore protégée.{extra}",
    'Once the TLS reports are clean, switch to "enforce".': "Quand les rapports TLS sont propres, passez à « enforce ».",
    'Policy in "enforce" mode, covering all mail servers: incoming email is always delivered encrypted.':
        "Politique en mode « enforce », couvrant tous les serveurs de mail : vos emails entrants sont toujours livrés "
        "chiffrés.",
    "TLS reporting (TLS-RPT)": "Rapports TLS (TLS-RPT)",
    "Present: sending servers report the delivery problems they meet.":
        "Présent : les serveurs expéditeurs signalent les problèmes de livraison rencontrés.",
    "Not set: you are not told when other servers fail to deliver your mail securely.":
        "Non défini : vous n'êtes pas prévenu quand d'autres serveurs n'arrivent pas à vous livrer vos emails de "
        "façon sûre.",
    'Publish a _smtp._tls TXT record, e.g. "v=TLSRPTv1; rua=mailto:tls-reports@your-domain".':
        "Publiez un enregistrement TXT _smtp._tls, par exemple « v=TLSRPTv1; rua=mailto:tls-reports@votre-domaine ».",
    # --- Domain & DNS ----------------------------------------------------------------
    "DNSSEC": "DNSSEC",
    "Could not be checked ({error}).": "Vérification impossible ({error}).",
    "the zone": "la zone",
    "Not enabled for {zone}: DNS answers are not signed, so a resolver cannot detect forged answers (redirecting "
    "visitors or emails to another server).":
        "Non activé pour {zone} : les réponses DNS ne sont pas signées, un résolveur ne peut donc pas détecter de "
        "fausses réponses (qui redirigeraient visiteurs ou emails vers un autre serveur).",
    "Enable DNSSEC at your DNS host, then publish the DS record at your registrar (often a single option in their "
    "interface).":
        "Activez DNSSEC chez votre hébergeur DNS, puis publiez l'enregistrement DS chez votre registrar (souvent une "
        "simple option dans son interface).",
    "publishes no DNSSEC key": "ne publie aucune clé DNSSEC",
    "has no key matching the DS record": "n'a aucune clé correspondant à l'enregistrement DS",
    "Broken: the parent zone announces DNSSEC for {zone}, but the zone {problem}. Validating resolvers (used by many "
    "ISPs and public DNS services) may refuse to resolve the domain.":
        "Cassé : la zone parente annonce DNSSEC pour {zone}, mais la zone {problem}. Les résolveurs qui valident "
        "DNSSEC (utilisés par de nombreux fournisseurs d'accès et DNS publics) peuvent refuser de résoudre le domaine.",
    "Fix it now: publish the right DS record at your registrar, or remove it if DNSSEC was turned off at your DNS "
    "host.":
        "Corrigez-le maintenant : publiez le bon enregistrement DS chez votre registrar, ou retirez-le si DNSSEC a été "
        "désactivé chez votre hébergeur DNS.",
    " (the DS record could not be compared with the keys)": " (l'enregistrement DS n'a pas pu être comparé aux clés)",
    "Enabled for {zone}: DNS answers are signed{unchecked}.": "Activé pour {zone} : les réponses DNS sont signées{unchecked}.",
    "CAA (allowed certificate authorities)": "CAA (autorités de certification autorisées)",
    "No CAA record: any certificate authority may issue a certificate for this domain.":
        "Aucun enregistrement CAA : n'importe quelle autorité de certification peut émettre un certificat pour ce "
        "domaine.",
    'Publish a CAA record naming the authority you use, e.g. 0 issue "letsencrypt.org".':
        "Publiez un enregistrement CAA qui nomme l'autorité que vous utilisez, par exemple 0 issue "
        "\"letsencrypt.org\".",
    " (published on {owner})": " (publié sur {owner})",
    "A CAA record uses an unknown tag marked critical ({tags}){where}: certificate authorities must then refuse to "
    "issue any certificate.":
        "Un enregistrement CAA utilise une balise inconnue marquée critique ({tags}){where} : les autorités de "
        "certification doivent alors refuser d'émettre tout certificat.",
    "Remove the critical flag (128) or fix the tag name.": "Retirez l'indicateur critique (128) ou corrigez le nom de la balise.",
    'CAA records exist{where} but none restricts issuance (no "issue" tag).':
        "Des enregistrements CAA existent{where} mais aucun ne restreint l'émission (pas de balise « issue »).",
    'Add an "issue" record naming the authority you use.': "Ajoutez un enregistrement « issue » qui nomme l'autorité que vous utilisez.",
    "CAA forbids every certificate authority{where}: the site's certificate cannot be renewed.":
        "CAA interdit toutes les autorités de certification{where} : le certificat du site ne pourra pas être "
        "renouvelé.",
    'Name the authority you use in an "issue" record.': "Indiquez l'autorité que vous utilisez dans un enregistrement « issue ».",
    "CAA forbids every certificate authority{where} (fine for a domain without a website).":
        "CAA interdit toutes les autorités de certification{where} (normal pour un domaine sans site web).",
    "Only these authorities may issue certificates{where}: {names}.":
        "Seules ces autorités peuvent émettre des certificats{where} : {names}.",
    # --- Changes since the previous audit --------------------------------------------
    "Changes since the audit of {date}": "Évolution depuis l'audit du {date}",
    "No change since the audit of {date}.": "Aucun changement depuis l'audit du {date}.",
    "Grades": "Notes",
    "{area}: {old} → {new}": "{area} : {old} → {new}",
    "Fixed ({count})": "Corrigés ({count})",
    "New problems ({count})": "Nouveaux problèmes ({count})",
    "Worse ({count})": "Aggravés ({count})",
    "Better ({count})": "Améliorés ({count})",
    "new check": "nouveau contrôle",
    "Since last audit": "Depuis le dernier audit",
    "first audit": "premier audit",
    "no change": "aucun changement",
    "grades changed": "notes modifiées",
    "{count} fixed": "{count} corrigé(s)",
    "{count} new or worse": "{count} nouveau(x) ou aggravé(s)",
    "{count} better": "{count} amélioré(s)",
    # --- Command line, errors -------------------------------------------------------
    "Reminder: only audit domains you own or for which you have the owner's permission.":
        "Rappel : n'auditez que vos propres domaines, ou ceux dont le propriétaire vous a donné l'autorisation.",
    "Error: {message}": "Erreur : {message}",
    "Audit stopped: {message}": "Audit interrompu : {message}",
    "No report was produced, to avoid a wrong diagnosis.": "Aucun rapport n'a été produit, pour éviter un diagnostic erroné.",
    "HTML report: {path}": "Rapport HTML : {path}",
    "PDF report: {path}": "Rapport PDF : {path}",
    "not audited: {reason}": "non audité : {reason}",
    "Summary: {path} ({audited} audited, {failed} not audited)": "Synthèse : {path} ({audited} audité(s), {failed} non audité(s))",
    "Invalid domain name: {name}": "Nom de domaine invalide : {name}",
    "No DNS server configured on this machine.": "Aucun serveur DNS n'est configuré sur cette machine.",
    "DNS resolution failed for {name} ({rtype}): check your connection.":
        "La résolution DNS a échoué pour {name} ({rtype}) : vérifiez votre connexion.",
    "DNS resolution failed for {domain}: check your connection.":
        "La résolution DNS a échoué pour {domain} : vérifiez votre connexion.",
    "The domain {domain} does not exist (or your network filters DNS queries).":
        "Le domaine {domain} n'existe pas (ou votre réseau filtre les requêtes DNS).",
    "Security audit of 1 domain": "Audit de sécurité d'un domaine",
    # --- Certificate errors (OpenSSL wording) ---------------------------------------
    "certificate has expired": "le certificat a expiré",
    "certificate is not yet valid": "le certificat n'est pas encore valide",
    "self-signed certificate": "certificat auto-signé",
    "self-signed certificate in certificate chain": "certificat auto-signé dans la chaîne de certification",
    "unable to get local issuer certificate": "autorité de certification inconnue (émetteur non reconnu)",
    "hostname mismatch: the certificate is not valid for '{host}'":
        "nom de domaine différent : le certificat n'est pas valide pour « {host} »",
    # --- Sources (titles of the standards) -------------------------------------------
    "W3C Content Security Policy Level 3": "W3C Content Security Policy niveau 3",
    "RFC 6265 (HTTP cookies) and MDN cookie guide": "RFC 6265 (cookies HTTP) et guide MDN sur les cookies",
    "MDN TLS guide: HTTP redirection": "Guide TLS de MDN : redirection HTTP",
    "RFC 6797 (HTTP Strict Transport Security)": "RFC 6797 (HTTP Strict Transport Security)",
    "HSTS preload list (Chromium, used by all major browsers)":
        "Liste HSTS préchargée (Chromium, utilisée par tous les grands navigateurs)",
    "W3C Subresource Integrity": "W3C Subresource Integrity",
    "W3C Referrer Policy": "W3C Referrer Policy",
    "WHATWG Fetch: X-Content-Type-Options": "WHATWG Fetch : X-Content-Type-Options",
    "RFC 7034 (X-Frame-Options)": "RFC 7034 (X-Frame-Options)",
    "MDN: Cross-Origin-Resource-Policy": "MDN : Cross-Origin-Resource-Policy",
    "MDN: Cross-Origin-Opener-Policy": "MDN : Cross-Origin-Opener-Policy",
    "MDN: Cross-Origin-Embedder-Policy": "MDN : Cross-Origin-Embedder-Policy",
    "W3C Permissions Policy": "W3C Permissions Policy",
    "OWASP Secure Headers Project": "OWASP Secure Headers Project",
    "MDN TLS guide": "Guide TLS de MDN",
    "RFC 8996 (deprecating TLS 1.0 and 1.1)": "RFC 8996 (abandon de TLS 1.0 et 1.1)",
    "RFC 7208 (SPF)": "RFC 7208 (SPF)",
    "RFC 7489 (DMARC)": "RFC 7489 (DMARC)",
    "RFC 6376 (DKIM)": "RFC 6376 (DKIM)",
    "RFC 7505 (null MX for domains that receive no email)": "RFC 7505 (MX nul pour les domaines qui ne reçoivent pas d'email)",
    "RFC 8461 (SMTP MTA Strict Transport Security)": "RFC 8461 (SMTP MTA Strict Transport Security)",
    "RFC 8460 (SMTP TLS Reporting)": "RFC 8460 (rapports TLS pour SMTP)",
    "RFC 4033 (DNS Security Introduction and Requirements)": "RFC 4033 (introduction et exigences de la sécurité DNS)",
    "RFC 8659 (DNS Certification Authority Authorization)": "RFC 8659 (autorisation des autorités de certification par DNS)",
    # --- Registration (RDAP) -----------------------------------------------------------
    # --- Branded PDF cover page ------------------------------------------------------------
    "Overall grade": "Note globale",
    "Prepared for {client}": "Préparé pour {client}",
    "Prepared by {who}": "Réalisé par {who}",
    "Confidential: this report describes security weaknesses. Share it only with the people in charge of fixing them.":
        "Confidentiel : ce rapport décrit des faiblesses de sécurité. Ne le transmettez qu'aux personnes chargées de "
        "les corriger.",
    # --- Outdated software -----------------------------------------------------------------
    "Software: {name}": "Logiciel : {name}",
    "Software on {host}: {name}": "Logiciel sur {host} : {name}",
    " on {host}": " sur {host}",
    " since {date}": " depuis le {date}",
    "generator tag of the page": "balise generator de la page",
    "addresses of the page's files": "adresses des fichiers de la page",
    "scripts of the page": "scripts de la page",
    "support dates unavailable": "dates de support indisponibles",
    "version not listed in the support dates": "version absente des dates de support",
    "{name} is used{where} ({seen}); its version is not shown, so whether it is up to date cannot be checked from "
    "outside.":
        "{name} est utilisé{where} ({seen}) ; sa version n'est pas affichée, donc impossible de vérifier depuis "
        "l'extérieur s'il est à jour.",
    "Check that {name} and its extensions are updated automatically.":
        "Vérifiez que {name} et ses extensions se mettent à jour automatiquement.",
    "{label} is used{where} ({seen}): this major version is still supported, but the exact version is not shown.":
        "{label} est utilisé{where} ({seen}) : cette version majeure est encore maintenue, mais la version exacte n'est "
        "pas affichée.",
    "{label} is used{where} ({seen}); {reason}.": "{label} est utilisé{where} ({seen}) ; {reason}.",
    "Check that {name} is a version that still gets security fixes.":
        "Vérifiez que cette version de {name} reçoit encore des correctifs de sécurité.",
    "{label}{where} no longer gets security fixes{since}: every flaw found since then stays open, and attackers scan "
    "for these versions automatically.":
        "{label}{where} ne reçoit plus de correctifs de sécurité{since} : toutes les failles découvertes depuis restent "
        "ouvertes, et les attaquants recherchent ces versions automatiquement.",
    "Upgrade {name} to a supported version (test on a copy of the site first), and hide the version number.":
        "Passez {name} à une version maintenue (testez d'abord sur une copie du site) et masquez le numéro de version.",
    "{label}{where} is not up to date: version {latest} fixes known problems.":
        "{label}{where} n'est pas à jour : la version {latest} corrige des problèmes connus.",
    "Update {name} to {latest} and turn on automatic minor updates.":
        "Mettez {name} à jour en {latest} et activez les mises à jour mineures automatiques.",
    "{label}{where} is a supported, up-to-date version (the number is still visible: hiding it gives attackers less "
    "to go on).":
        "{label}{where} est une version maintenue et à jour (le numéro reste visible : le masquer donne moins "
        "d'indices aux attaquants).",
    "Outdated software on the site has known flaws that attackers exploit automatically.":
        "Des logiciels obsolètes sur le site ont des failles connues que les attaquants exploitent automatiquement.",
    # --- Subdomains in use ---------------------------------------------------------------
    "Subdomains: HTTPS certificates": "Sous-domaines : certificats HTTPS",
    "Subdomains: no HTTPS": "Sous-domaines : pas de HTTPS",
    "Subdomains: HTTP to HTTPS redirect": "Sous-domaines : redirection HTTP vers HTTPS",
    "Subdomains: obsolete TLS versions": "Sous-domaines : versions de TLS obsolètes",
    "{count} subdomain(s) in use checked, {web} with a website.":
        "{count} sous-domaine(s) en service vérifié(s), dont {web} avec un site web.",
    "{seen} Certificate not valid: {hosts}. Visitors get a security warning.":
        "{seen} Certificat non valide : {hosts}. Les visiteurs voient une alerte de sécurité.",
    "{seen} Every certificate is valid.": "{seen} Tous les certificats sont valides.",
    "Renew or replace these certificates, or delete the subdomains no longer used.":
        "Renouvelez ou remplacez ces certificats, ou supprimez les sous-domaines qui ne servent plus.",
    "These subdomains only answer over unencrypted HTTP: {hosts}.":
        "Ces sous-domaines ne répondent qu'en HTTP non chiffré : {hosts}.",
    "Enable HTTPS on these subdomains (a free Let's Encrypt certificate is enough).":
        "Activez le HTTPS sur ces sous-domaines (un certificat Let's Encrypt gratuit suffit).",
    "These subdomains are still reachable over HTTP without a redirect to HTTPS: {hosts}.":
        "Ces sous-domaines restent accessibles en HTTP sans redirection vers HTTPS : {hosts}.",
    "Redirect HTTP to HTTPS (301) on these subdomains too.":
        "Redirigez aussi HTTP vers HTTPS (301) sur ces sous-domaines.",
    "These subdomains still accept TLS 1.0 or 1.1: {hosts}.": "Ces sous-domaines acceptent encore TLS 1.0 ou 1.1 : {hosts}.",
    "Only allow TLS 1.2 and 1.3 on these subdomains too.": "N'autorisez que TLS 1.2 et 1.3 sur ces sous-domaines aussi.",
    # --- NIS 2 view (summaries of article 21(2), not quotations) -------------------------
    "NIS 2 view (article 21)": "Lecture NIS 2 (article 21)",
    "Directive (EU) 2022/2555 (NIS 2) lists in its article 21(2) the cybersecurity measures that essential and "
    "important entities must take. From the Internet, this audit gives evidence for some of them only: this table "
    "links each check to a measure, it is not a compliance assessment.":
        "La directive (UE) 2022/2555 (NIS 2) liste dans son article 21(2) les mesures de cybersécurité que les entités "
        "essentielles et importantes doivent prendre. Depuis Internet, cet audit n'apporte des éléments que pour "
        "certaines d'entre elles : ce tableau relie chaque contrôle à une mesure, ce n'est pas une évaluation de "
        "conformité.",
    "Read the directive": "Lire la directive",
    "Measure": "Mesure",
    "In this audit": "Dans cet audit",
    "Result": "Résultat",
    "{count} check(s)": "{count} contrôle(s)",
    "{count} problem(s): {names}": "{count} problème(s) : {names}",
    "No problem seen in the related checks.": "Aucun problème relevé dans les contrôles liés.",
    "Not visible from outside: depends on internal organisation and documents.":
        "Invisible depuis l'extérieur : dépend de l'organisation et des documents internes.",
    "Risk analysis and information system security policies":
        "Politiques d'analyse des risques et de sécurité des systèmes d'information",
    "Incident handling": "Gestion des incidents",
    "Business continuity (backups, disaster recovery, crisis management)":
        "Continuité des activités (sauvegardes, reprise après sinistre, gestion de crise)",
    "Supply chain security": "Sécurité de la chaîne d'approvisionnement",
    "Security in acquisition, development and maintenance, including vulnerability handling and disclosure":
        "Sécurité de l'acquisition, du développement et de la maintenance, dont le traitement et la divulgation des "
        "vulnérabilités",
    "Assessing the effectiveness of the risk-management measures":
        "Évaluation de l'efficacité des mesures de gestion des risques",
    "Basic cyber hygiene practices and cybersecurity training":
        "Pratiques de base de cyberhygiène et formation à la cybersécurité",
    "Use of cryptography and encryption": "Utilisation de la cryptographie et du chiffrement",
    "Human resources security, access control and asset management":
        "Sécurité des ressources humaines, contrôle d'accès et gestion des actifs",
    "Multi-factor authentication and secured communications":
        "Authentification à plusieurs facteurs et communications sécurisées",
    # --- Summary for decision makers -----------------------------------------------------
    "Summary for decision makers": "Synthèse pour la direction",
    "Main risks": "Principaux risques",
    "Effort": "Effort",
    "No priority action: keep these settings and audit the domain again regularly.":
        "Aucune action prioritaire : conservez ces réglages et refaites un audit régulièrement.",
    "Applying the quick fixes alone would raise the overall grade from {before} to {after}.":
        "Les seules corrections rapides feraient passer la note globale de {before} à {after}.",
    "{quick} quick fix(es) (under 30 min each), {hours} of a few hours, {projects} project(s) needing a developer or "
    "a provider.":
        "{quick} correction(s) rapide(s) (moins de 30 min chacune), {hours} de quelques heures, {projects} chantier(s) "
        "demandant un développeur ou un prestataire.",
    "Quick fix (under 30 min)": "Correction rapide (moins de 30 min)",
    "A few hours": "Quelques heures",
    "Project (developer or provider)": "Chantier (développeur ou prestataire)",
    "High impact": "Impact fort",
    "Medium impact": "Impact moyen",
    "Low impact": "Impact faible",
    "Visitors' data (forms, logins) can be intercepted, for instance on public Wi-Fi.":
        "Les données des visiteurs (formulaires, identifiants) peuvent être interceptées, par exemple sur un Wi-Fi "
        "public.",
    "Visitors get a security warning, or their data can be intercepted.":
        "Les visiteurs voient une alerte de sécurité, ou leurs données peuvent être interceptées.",
    "Old encryption weakens the protection of visitors' data.":
        "Un chiffrement dépassé affaiblit la protection des données des visiteurs.",
    "A flaw in the site or in a third-party script can be used to steal visitors' data (XSS).":
        "Une faille du site ou d'un script tiers peut servir à voler les données des visiteurs (XSS).",
    "The site can be shown inside a fake site to trick visitors into clicking (clickjacking).":
        "Le site peut être affiché dans un faux site pour piéger les visiteurs (clickjacking).",
    "Session cookies can be stolen, giving access to users' accounts.":
        "Les cookies de session peuvent être volés et donner accès aux comptes des utilisateurs.",
    "Visible software versions make known flaws easier to target.":
        "Les versions de logiciels visibles facilitent l'exploitation de failles connues.",
    "Anyone can send emails in the company's name: phishing of clients, fake invoices.":
        "N'importe qui peut envoyer des emails au nom de l'entreprise : hameçonnage des clients, fausses factures.",
    "Emails sent to the company can be read or altered on the way.":
        "Les emails envoyés à l'entreprise peuvent être lus ou modifiés en route.",
    "Visitors and emails can be sent to a fake server through forged DNS answers.":
        "Visiteurs et emails peuvent être détournés vers un faux serveur par de fausses réponses DNS.",
    "Any certificate authority can issue a certificate for the domain.":
        "N'importe quelle autorité de certification peut émettre un certificat pour le domaine.",
    "The domain can expire: website and email down, and the name can be taken by someone else.":
        "Le domaine peut expirer : site et emails coupés, et le nom peut être repris par quelqu'un d'autre.",
    "With a stolen registrar password, the domain can be moved elsewhere.":
        "Avec un mot de passe volé chez le bureau d'enregistrement, le domaine peut être transféré ailleurs.",
    "A forgotten subdomain can be taken over to publish content in the company's name.":
        "Un sous-domaine oublié peut être détourné pour publier du contenu au nom de l'entreprise.",
    # --- DKIM: keys and sending services -------------------------------------------------
    "DKIM for each sending service": "DKIM pour chaque service d'envoi",
    "{found} Keys under 1024 bits can be broken: someone could then sign emails in your name: {weak}.":
        "{found} Les clés de moins de 1024 bits peuvent être cassées : quelqu'un pourrait alors signer des emails à "
        "votre nom : {weak}.",
    "Generate a new 2048-bit DKIM key in your email service and delete the old record.":
        "Générez une nouvelle clé DKIM de 2048 bits dans votre service de messagerie et supprimez l'ancien "
        "enregistrement.",
    "{found} 1024-bit keys are still accepted but now considered too short; 2048 bits is the current recommendation: "
    "{short}.":
        "{found} Les clés de 1024 bits sont encore acceptées mais jugées trop courtes aujourd'hui ; 2048 bits est la "
        "recommandation actuelle : {short}.",
    "Switch to a 2048-bit DKIM key when your email service allows it (key rotation).":
        "Passez à une clé DKIM de 2048 bits dès que votre service de messagerie le permet (rotation de clé).",
    "No DKIM key found among the common selectors tested ({count}), including the usual ones of the services named "
    "in SPF ({senders}): DKIM signing is probably not enabled for them.":
        "Aucune clé DKIM trouvée parmi les sélecteurs courants testés ({count}), y compris ceux habituels des services "
        "cités dans SPF ({senders}) : la signature DKIM n'est probablement pas activée chez eux.",
    "SPF allows these services to send for the domain, but their usual DKIM keys were not found: {senders}. Their "
    "emails may be signed with their own domain, which DMARC does not count as yours.":
        "SPF autorise ces services à envoyer pour le domaine, mais leurs clés DKIM habituelles sont introuvables : "
        "{senders}. Leurs emails sont peut-être signés avec leur propre domaine, que DMARC ne compte pas comme le "
        "vôtre.",
    "Enable DKIM with your own domain in each of these services.":
        "Activez DKIM avec votre propre domaine dans chacun de ces services.",
    # --- Mail servers ----------------------------------------------------------------
    "Mail servers: encryption": "Serveurs de mail : chiffrement",
    "Encryption of incoming email (STARTTLS)": "Chiffrement des emails reçus (STARTTLS)",
    "Mail server TLS version": "Version TLS des serveurs de mail",
    "Mail server certificates": "Certificats des serveurs de mail",
    "DANE (mail server keys in DNS)": "DANE (clés des serveurs de mail dans le DNS)",
    "no answer": "pas de réponse",
    "Could not connect to the mail servers on port 25 ({error}). This port is often blocked by the network the audit "
    "runs from (home connections, cloud providers): nothing can be concluded.":
        "Connexion impossible aux serveurs de mail sur le port 25 ({error}). Ce port est souvent bloqué par le réseau "
        "d'où l'audit est lancé (connexions domestiques, hébergeurs cloud) : rien ne peut en être conclu.",
    "Run the audit from a network that allows outgoing connections on port 25.":
        "Relancez l'audit depuis un réseau qui autorise les connexions sortantes sur le port 25.",
    " Not reached: {hosts}.": " Non joints : {hosts}.",
    "These mail servers do not offer encryption: emails sent to you travel in clear text and can be read on the way: "
    "{hosts}.{unreached}":
        "Ces serveurs de mail ne proposent pas de chiffrement : les emails qui vous sont envoyés circulent en clair et "
        "peuvent être lus en route : {hosts}.{unreached}",
    "Enable STARTTLS with a valid certificate on these servers (or ask your email provider).":
        "Activez STARTTLS avec un certificat valide sur ces serveurs (ou demandez-le à votre fournisseur de "
        "messagerie).",
    "Every mail server reached offers encryption ({versions}).{unreached}":
        "Tous les serveurs de mail joints proposent le chiffrement ({versions}).{unreached}",
    "These mail servers negotiate an obsolete TLS version with a current sender: {hosts}.":
        "Ces serveurs de mail négocient une version obsolète de TLS avec un expéditeur actuel : {hosts}.",
    "Allow TLS 1.2 and 1.3 on these servers.": "Autorisez TLS 1.2 et 1.3 sur ces serveurs.",
    "{host} (expired on {date})": "{host} (expiré le {date})",
    "Your MTA-STS policy is in enforce mode, but these certificates are not valid: senders that apply MTA-STS (Gmail, "
    "Outlook...) will refuse to deliver emails to you: {hosts}.":
        "Votre politique MTA-STS est en mode « enforce », mais ces certificats ne sont pas valides : les expéditeurs "
        "qui appliquent MTA-STS (Gmail, Outlook...) refuseront de vous livrer les emails : {hosts}.",
    "Install a valid certificate for the server's name now, or switch MTA-STS to testing mode until it is fixed.":
        "Installez dès maintenant un certificat valide pour le nom du serveur, ou passez MTA-STS en mode « testing » "
        "le temps de corriger.",
    "Not valid: {hosts}. Senders still encrypt, but cannot check they reach the real server, and MTA-STS or DANE "
    "cannot be enforced.":
        "Non valides : {hosts}. Les expéditeurs chiffrent quand même, mais ne peuvent pas vérifier qu'ils joignent le "
        "vrai serveur, et MTA-STS ou DANE ne peuvent pas être appliqués.",
    "Install a certificate valid for the mail server's name (Let's Encrypt is free).":
        "Installez un certificat valide pour le nom du serveur de mail (Let's Encrypt est gratuit).",
    "The certificates of the mail servers are valid.": "Les certificats des serveurs de mail sont valides.",
    "Every mail server publishes TLSA records: senders that support DANE check the server's key through DNSSEC.":
        "Chaque serveur de mail publie des enregistrements TLSA : les expéditeurs compatibles DANE vérifient la clé du "
        "serveur grâce à DNSSEC.",
    " by {hosts}": " par {hosts}",
    "Not used{partial}. Optional: DANE lets senders check the mail server's key through DNSSEC, and is required by "
    "some administrations.":
        "Non utilisé{partial}. Facultatif : DANE permet aux expéditeurs de vérifier la clé du serveur de mail grâce à "
        "DNSSEC, et certaines administrations l'exigent.",
    "If the domain uses DNSSEC, publish a TLSA record for each mail server (_25._tcp.<server>), or ask your email "
    "provider.":
        "Si le domaine utilise DNSSEC, publiez un enregistrement TLSA pour chaque serveur de mail (_25._tcp.<serveur>), "
        "ou demandez-le à votre fournisseur de messagerie.",
    # --- Fixes per hosting platform (menu names stay in English, as in the providers' interfaces) ---
    "Documentation": "Documentation",
    "On {platform}:": "Sur {platform} :",
    "On {provider}:": "Chez {provider} :",
    "On {platform} (.htaccess):": "Sur {platform} (.htaccess) :",
    "On nginx (server block listening on port 80):": "Sur nginx (bloc server qui écoute le port 80) :",
    "On Apache (main configuration; for PHP, expose_php = Off in php.ini):":
        "Sur Apache (configuration principale ; pour PHP, expose_php = Off dans php.ini) :",
    "On Cloudflare:": "Sur Cloudflare :",
    "On Google Workspace:": "Sur Google Workspace :",
    "On Microsoft 365:": "Sur Microsoft 365 :",
    "In web.config (system.webServer > httpProtocol > customHeaders):":
        "Dans web.config (system.webServer > httpProtocol > customHeaders) :",
    "In the _headers file of the site (Netlify):": "Dans le fichier _headers du site (Netlify) :",
    "In vercel.json:": "Dans vercel.json :",
    "add the header {name}: {value} with a response header Transform Rule (Rules section of the dashboard), or on "
    "the origin server.":
        "ajoutez l'en-tête {name}: {value} avec une Transform Rule de réponse (section Rules du tableau de bord), ou "
        "sur le serveur d'origine.",
    "HTTP headers cannot be added. Put the site behind a service that can add them (a CDN such as Cloudflare) or "
    "move it to a host that allows it.":
        "impossible d'ajouter des en-têtes HTTP. Placez le site derrière un service qui le permet (un CDN comme "
        "Cloudflare) ou changez d'hébergeur.",
    "Edge Certificates > HTTP Strict Transport Security (HSTS) > Enable HSTS.":
        "Edge Certificates > HTTP Strict Transport Security (HSTS) > Enable HSTS.",
    "Edge Certificates > Always Use HTTPS.": "Edge Certificates > Always Use HTTPS.",
    "Settings > Pages > Enforce HTTPS, in the site's repository.":
        "Settings > Pages > Enforce HTTPS, dans le dépôt du site.",
    "Edge Certificates > Minimum TLS Version: TLS 1.2 (TLS 1.3 is set on the same page).":
        "Edge Certificates > Minimum TLS Version : TLS 1.2 (TLS 1.3 se règle sur la même page).",
    "the Mozilla SSL Configuration Generator gives a ready configuration for this server (\"Intermediate\" profile).":
        "le générateur de configuration TLS de Mozilla donne une configuration prête pour ce serveur (profil "
        "« Intermediate »).",
    "Admin console > Apps > Google Workspace > Gmail > Authenticate email, then Generate new record and Start "
    "authentication.":
        "Console d'administration > Apps > Google Workspace > Gmail > Authenticate email, puis Generate new record et "
        "Start authentication.",
    "Defender portal > Policies & rules > Threat policies > Email authentication settings > DKIM.":
        "Portail Defender > Policies & rules > Threat policies > Email authentication settings > DKIM.",
    "turn on DKIM signing in the email administration interface, then publish the record it gives.":
        "activez la signature DKIM dans l'interface d'administration de la messagerie, puis publiez "
        "l'enregistrement qu'elle fournit.",
    "DNS > Settings > Enable DNSSEC, then copy the DS record to the registrar.":
        "DNS > Settings > Enable DNSSEC, puis recopiez l'enregistrement DS chez le bureau d'enregistrement.",
    "turn on DNSSEC in the settings of the DNS zone.": "activez DNSSEC dans les réglages de la zone DNS.",
    "add or edit the record in the DNS zone of the domain.": "ajoutez ou modifiez l'enregistrement dans la zone DNS du domaine.",
    "crt.sh did not answer, so the names come from Cert Spotter, which may list fewer old certificates: forgotten "
    "subdomains can be missing. Run the audit again later for a complete check.":
        "crt.sh n'a pas répondu : les noms viennent de Cert Spotter, qui peut lister moins d'anciens certificats, donc "
        "des sous-domaines oubliés peuvent manquer. Relancez l'audit plus tard pour un contrôle complet.",
    "{detail} {note}": "{detail} {note}",
    "Forgotten subdomains (CT logs)": "Sous-domaines oubliés (journaux CT)",
    "CT logs could not be read ({errors})": "les journaux CT n'ont pas pu être lus ({errors})",
    "No subdomain found in Certificate Transparency logs ({source}).":
        "Aucun sous-domaine trouvé dans les journaux Certificate Transparency ({source}).",
    "{count} subdomain(s) found in Certificate Transparency logs ({source}), {active} still in use{unknown}.":
        "{count} sous-domaine(s) trouvé(s) dans les journaux Certificate Transparency ({source}), dont {active} encore "
        "utilisé(s){unknown}.",
    " ({count} could not be looked up)": " ({count} n'ont pas pu être résolus)",
    "{seen} These subdomains point to a resource that no longer exists at a provider where anyone can create it "
    "again, and then publish content on your domain (subdomain takeover): {listed}.":
        "{seen} Ces sous-domaines pointent vers une ressource qui n'existe plus chez un fournisseur où n'importe qui "
        "peut la recréer, puis publier du contenu sur votre domaine (prise de contrôle de sous-domaine) : {listed}.",
    "Delete these DNS records now, or recreate the resource at the provider before someone else does.":
        "Supprimez ces enregistrements DNS dès maintenant, ou recréez la ressource chez le fournisseur avant que "
        "quelqu'un d'autre ne le fasse.",
    "{seen} These subdomains point to a name that no longer exists: {listed}.":
        "{seen} Ces sous-domaines pointent vers un nom qui n'existe plus : {listed}.",
    "Delete the DNS records of subdomains that are no longer used.":
        "Supprimez les enregistrements DNS des sous-domaines qui ne servent plus.",
    " In use: {names}.": " Utilisés : {names}.",
    "{names} and {count} more": "{names} et {count} autres",
    "{seen} None points to a resource that no longer exists.{active}":
        "{seen} Aucun ne pointe vers une ressource qui n'existe plus.{active}",
    "CAA and the current certificate": "CAA et certificat actuel",
    "none": "aucune",
    "no authority": "aucune autorité",
    "The authority of the current certificate ({issuer}) is not in this tool's list, so whether CAA allows it was not "
    "checked. Allowed: {allowed}.":
        "L'autorité du certificat actuel ({issuer}) ne figure pas dans la liste de l'outil : sa compatibilité avec la "
        "CAA n'a pas été vérifiée. Autorisées : {allowed}.",
    "The current certificate comes from {issuer}, which CAA allows: renewals will be accepted.":
        "Le certificat actuel vient de {issuer}, que la CAA autorise : les renouvellements seront acceptés.",
    "The current certificate comes from {issuer}, but CAA only allows {allowed}: the certificate stays valid, but its "
    "renewal by the same authority will be refused, and the site will show an error when it expires.":
        "Le certificat actuel vient de {issuer}, mais la CAA n'autorise que {allowed} : le certificat reste valide, "
        "mais son renouvellement par la même autorité sera refusé, et le site affichera une erreur à son expiration.",
    "Add \"{id}\" to the CAA records ({tag}), or switch to an allowed authority before the certificate expires.":
        "Ajoutez « {id} » aux enregistrements CAA ({tag}), ou passez à une autorité autorisée avant l'expiration du "
        "certificat.",
    "Domain expiry date": "Date d'expiration du domaine",
    "Transfer lock": "Verrou de transfert",
    "no RDAP server for this extension": "aucun serveur RDAP pour cette extension",
    "unreadable answer": "réponse illisible",
    " Registrar: {name}.": " Registrar : {name}.",
    "The registry does not publish the expiry date of {domain}.{registrar}":
        "Le registre ne publie pas la date d'expiration de {domain}.{registrar}",
    "The domain {domain} expired on {date}: the website and the email will stop working, and someone else could "
    "register the name.{registrar}":
        "Le domaine {domain} a expiré le {date} : le site et les emails vont cesser de fonctionner, et quelqu'un d'autre pourrait "
        "enregistrer ce nom.{registrar}",
    "Renew the domain immediately at your registrar.": "Renouvelez le domaine immédiatement chez votre registrar.",
    "The domain {domain} expires in {days} day(s), on {date}.{registrar}": "Le domaine {domain} expire dans {days} jour(s), le {date}.{registrar}",
    "Renew it now and turn on automatic renewal at your registrar.":
        "Renouvelez-le maintenant et activez le renouvellement automatique chez votre registrar.",
    "The domain {domain} expires in {days} days, on {date}.{registrar}": "Le domaine {domain} expire dans {days} jours, le {date}.{registrar}",
    "Check that automatic renewal is on and that the payment card is valid.":
        "Vérifiez que le renouvellement automatique est activé et que la carte de paiement est valide.",
    "The domain {domain} is registered until {date} ({days} days).{registrar}":
        "Le domaine {domain} est enregistré jusqu'au {date} ({days} jours).{registrar}",
    "The domain is locked against transfers to another registrar.":
        "Le domaine est verrouillé contre les transferts vers un autre registrar.",
    "The domain is not locked against transfers: with a stolen access to your registrar account, it is easier to "
    "move it elsewhere.":
        "Le domaine n'est pas verrouillé contre les transferts : avec un accès volé à votre compte chez le registrar, "
        "il est plus facile de le déplacer ailleurs.",
    'Turn on the transfer lock (often called "registrar lock") at your registrar.':
        "Activez le verrou de transfert (souvent appelé « registrar lock ») chez votre registrar.",
    "RFC 9083 (RDAP, registration data of domain names)": "RFC 9083 (RDAP, données d'enregistrement des noms de domaine)",
    "RFC 5731 (domain status, including transfer prohibited)":
        "RFC 5731 (statuts d'un domaine, dont l'interdiction de transfert)",
    "ANSSI TLS guide v1.2 (2020)": "Guide ANSSI TLS v1.2 (2020)",
    "ANSSI website guide PA-009 v2.0 (2021)": "Guide ANSSI site web PA-009 v2.0 (2021)",
    "ANSSI domain name guide BP-038 v1.3 (2017)": "Guide ANSSI noms de domaine BP-038 v1.3 (2017)",
    "ANSSI Internet gateway guide PA-066 v3.0 (2020)": "Guide ANSSI interconnexion à Internet PA-066 v3.0 (2020)",
    "RFC 9162 (Certificate Transparency)": "RFC 9162 (Certificate Transparency)",
    "RFC 3207 (STARTTLS for SMTP)": "RFC 3207 (STARTTLS pour SMTP)",
    "RFC 7672 (DANE for SMTP)": "RFC 7672 (DANE pour SMTP)",
    "endoflife.date (end of support dates of software versions)":
        "endoflife.date (dates de fin de support des versions de logiciels)",
    "RFC 8446 (TLS 1.3)": "RFC 8446 (TLS 1.3)",
    "RFC 9325 (recommendations for the secure use of TLS)": "RFC 9325 (recommandations pour un usage sûr de TLS)",
    "CNIL personal data security guide (2024): securing websites":
        "Guide CNIL de la sécurité des données personnelles (2024) : sécuriser les sites web",
    # --- security.txt ------------------------------------------------------------------
    "security.txt (vulnerability reporting)": "security.txt (signalement de failles)",
    "RFC 9116 (security.txt)": "RFC 9116 (security.txt)",
    "No security.txt file: someone who finds a vulnerability on the site does not know whom to warn.":
        "Aucun fichier security.txt : une personne qui trouve une faille sur le site ne sait pas qui prévenir.",
    "Publish /.well-known/security.txt with at least a Contact and an Expires field (for example generated on "
    "securitytxt.org).":
        "Publiez /.well-known/security.txt avec au moins un champ Contact et un champ Expires (par exemple généré sur "
        "securitytxt.org).",
    " (at the old address /security.txt; the standard one is /.well-known/security.txt)":
        " (à l'ancienne adresse /security.txt ; l'adresse standard est /.well-known/security.txt)",
    "The file has no Contact field{where}.": "Le fichier n'a pas de champ Contact{where}.",
    "Add a Contact line, for example Contact: mailto:security@your-domain.":
        "Ajoutez une ligne Contact, par exemple Contact: mailto:securite@votre-domaine.",
    "The file has no valid Expires field (exactly one date is required){where}.":
        "Le fichier n'a pas de champ Expires valide (une seule date est exigée){where}.",
    "Add an Expires line, for example Expires: 2027-01-01T00:00:00Z, and renew it every year.":
        "Ajoutez une ligne Expires, par exemple Expires: 2027-01-01T00:00:00Z, et renouvelez-la chaque année.",
    "The file expired on {date}: it should no longer be trusted{where}.":
        "Le fichier a expiré le {date} : il ne doit plus être considéré comme fiable{where}.",
    "Update the file and its Expires date (at most one year ahead).":
        "Mettez à jour le fichier et sa date Expires (au plus un an à l'avance).",
    "Present: contact {contact}, valid until {date}{where}.": "Présent : contact {contact}, valide jusqu'au {date}{where}.",
}
