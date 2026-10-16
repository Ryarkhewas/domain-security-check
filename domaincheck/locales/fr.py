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
    "this project's scale (RFC 8996, certificate validity)": "barème du projet (RFC 8996, validité du certificat)",
    "this project's scale (RFC 7208, 7489, 6376, 8461)": "barème du projet (RFC 7208, 7489, 6376, 8461)",
    "this project's scale (RFC 4033, 8659)": "barème du projet (RFC 4033, 8659)",
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
        "La note du site web suit le barème de {link} (pénalités et bonus par en-tête). Les notes certificat, email et "
        "DNS suivent le barème propre au projet, fondé sur les normes citées sous chaque point. La note globale est la "
        "plus basse des quatre.",
    "This audit does not cover the site's applications, workstations or user accounts. It gives an overview of the "
    "exposure visible from the Internet on the date shown.":
        "Cet audit ne couvre pas les applications du site, les postes de travail ni les comptes utilisateurs. Il donne "
        "une vue d'ensemble de l'exposition visible depuis Internet à la date indiquée.",
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
}
