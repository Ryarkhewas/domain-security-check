# Autorisation d'audit de sécurité externe

> **Modèle indicatif.** Ce document aide à cadrer un audit réalisé avec domain-security-check. Il ne remplace pas
> l'avis d'un juriste : adaptez-le à votre situation (contrat de prestation, conditions générales, assurance).
> Les passages entre crochets `[ ]` sont à compléter ; supprimez les options qui ne s'appliquent pas.

## 1. Les parties

**Le client**, qui autorise l'audit :
- Raison sociale : [Nom de l'entreprise] — SIREN : [numéro]
- Représenté par : [Prénom Nom], [fonction], habilité à engager l'entreprise
- Adresse : [adresse]

**L'auditeur**, qui réalise l'audit :
- Nom ou raison sociale : [Prénom Nom / entreprise] — SIRET : [numéro, si applicable]
- Adresse : [adresse]
- Contact : [adresse e-mail], [téléphone]

## 2. Objet

Le client autorise l'auditeur à réaliser un audit de l'exposition de sécurité visible depuis Internet des domaines
listés ci-dessous, avec l'outil open source domain-security-check
(https://github.com/Ryarkhewas/domain-security-check), version [1.x.x].

## 3. Périmètre

| Domaine | Inclus |
|---|---|
| [exemple.fr] | Site web, certificat et TLS, messagerie (SPF, DKIM, DMARC, serveurs de messagerie), DNS |
| [boutique.exemple.fr] | [idem / préciser] |

**Options** (cocher celles qui sont autorisées) :
- [ ] **Sous-domaines actifs** (`--subdomains`) : les sous-domaines trouvés dans les journaux publics de
  certificats (Certificate Transparency) et encore en service reçoivent quelques requêtes chacun (connexion HTTPS,
  versions TLS acceptées, page d'accueil, redirection HTTP).
- [ ] **Navigateur réel** (`--browser`) : la page d'accueil est ouverte dans un navigateur (Chromium) pour relever
  les traceurs chargés avant tout consentement, comme le ferait un visiteur.
- [ ] **Surveillance régulière** (`--alert`) : le même audit est relancé [chaque semaine / chaque mois] du
  [date] au [date], avec envoi des alertes à [adresse e-mail ou canal].

**Hors périmètre** : tout domaine, sous-domaine ou adresse IP non listé ci-dessus, ainsi que les applications du
site (formulaires, espaces clients), les postes de travail et les comptes utilisateurs.

## 4. Ce que fait l'outil, et ce qu'il ne fait pas

L'outil se comporte comme un visiteur ou un serveur de messagerie ordinaire :
- requêtes DNS publiques ;
- connexions HTTPS et HTTP à la page d'accueil, à `robots.txt`, `security.txt` et, le cas échéant, à la politique
  MTA-STS ; une requête de contrôle CORS (OPTIONS) sur la page d'accueil ;
- quelques débuts de connexion TLS (message ClientHello) pour connaître les versions et suites de chiffrement
  acceptées, sans échange de données ;
- connexion aux serveurs de messagerie sur le port 25 : EHLO, STARTTLS, poignée de main TLS, QUIT ; **aucun e-mail
  n'est envoyé** ;
- lecture de sources publiques : journaux Certificate Transparency, registre du domaine (RDAP), liste de
  préchargement HSTS, dates de fin de support des logiciels.

L'outil **ne fait pas** : de scan de ports, de recherche de répertoires ou de fichiers cachés, de test d'intrusion,
d'exploitation de faille, d'essai de mot de passe, de test de déni de service.

## 5. Calendrier

- Date(s) de l'audit : du [date] au [date], entre [heure] et [heure].
- Adresse IP ou réseau d'où l'audit est lancé : [adresse IP / « GitHub Actions » / à préciser].

## 6. Contacts et arrêt

- Contact technique côté client : [Prénom Nom], [e-mail], [téléphone].
- Le client peut demander l'arrêt immédiat de l'audit à tout moment, par [e-mail / téléphone] ; l'auditeur
  s'arrête dès réception.
- Si l'auditeur constate un problème grave (par exemple un sous-domaine pouvant être pris par un tiers), il prévient
  le contact technique [sous 24 heures / immédiatement], sans attendre le rapport.

## 7. Déclaration du client

Le client déclare être titulaire des domaines du périmètre, ou disposer de l'accord de leur titulaire, et être en
droit d'autoriser cet audit. Lorsque les services sont hébergés ou opérés par un prestataire (hébergeur, fournisseur
de messagerie, CDN), il appartient au client de vérifier que ses contrats l'autorisent à faire réaliser cet audit.

## 8. Confidentialité des résultats

Les rapports décrivent les faiblesses du client : ils sont confidentiels.
- Ils sont remis uniquement à [destinataire(s)], par [moyen de transmission].
- L'auditeur les conserve [durée, par exemple 12 mois] puis les supprime, sauf accord écrit du client.
- L'auditeur ne publie ni ne communique les résultats à un tiers sans accord écrit du client. Un exemple anonymisé
  ne peut être utilisé qu'avec cet accord.
- L'audit ne collecte aucune donnée personnelle des visiteurs ou des salariés du client. [Si des données
  personnelles apparaissent malgré tout (par exemple une adresse de contact dans security.txt), elles ne sont
  utilisées que pour l'audit.]

## 9. Responsabilité

L'audit donne un état de l'exposition visible depuis Internet à la date de l'analyse ; il ne garantit pas
l'absence d'autres failles. Les requêtes envoyées sont celles d'un visiteur ordinaire ; l'auditeur ne peut être tenu
responsable d'une indisponibilité qui ne résulterait pas d'un manquement de sa part au présent document.
[Préciser, le cas échéant, l'assurance responsabilité civile professionnelle de l'auditeur.]

## 10. Cadre légal

Accéder ou se maintenir sans droit dans un système informatique est puni par l'article 323-1 du Code pénal. La
présente autorisation, signée avant l'audit, définit ce que l'auditeur est autorisé à faire. Toute action en
dehors du périmètre et des méthodes décrits ici n'est pas couverte.

## Signatures

Fait à [ville], le [date], en deux exemplaires.

| Pour le client | Pour l'auditeur |
|---|---|
| [Prénom Nom, fonction] | [Prénom Nom] |
| Signature : | Signature : |
