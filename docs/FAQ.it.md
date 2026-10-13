# Domande frequenti

Questa FAQ risponde alle domande più comuni su Elementary CTI: che cos'è,
come ottenere l'accesso, da dove provengono i dati, come eseguire una propria
istanza e come risolvere i problemi più comuni. Viene renderizzata live su
`/faq` in ogni deployment.

## Indice

* [Il progetto](#il-progetto)
  * [Che cos'è Elementary CTI?](#che-cosè-elementary-cti)
  * [Perché si chiama "Elementary"?](#perché-si-chiama-elementary)
  * [È un prodotto commerciale?](#è-un-prodotto-commerciale)
  * [A chi è rivolto?](#a-chi-è-rivolto)
* [Accesso e account](#accesso-e-account)
  * [Perché vedo solo una piccola dashboard e un riquadro di accesso?](#perché-vedo-solo-una-piccola-dashboard-e-un-riquadro-di-accesso)
  * [Come ottengo un account?](#come-ottengo-un-account)
  * [Quali sono i ruoli?](#quali-sono-i-ruoli)
  * [Come effettuo l'accesso?](#come-effettuo-laccesso)
  * [Quanto dura una sessione?](#quanto-dura-una-sessione)
  * [Ho sbagliato la password diverse volte e ora sono bloccato. Cosa faccio?](#ho-sbagliato-la-password-diverse-volte-e-ora-sono-bloccato-cosa-faccio)
  * [Posso cambiare la password?](#posso-cambiare-la-password)
  * [Perché sono stato disconnesso senza preavviso?](#perché-sono-stato-disconnesso-senza-preavviso)
* [La dashboard pubblica e il TLP](#la-dashboard-pubblica-e-il-tlp)
  * [Cosa mostra esattamente la dashboard pubblica?](#cosa-mostra-esattamente-la-dashboard-pubblica)
  * [Che cos'è il TLP e come lo applica questo sito?](#che-cosè-il-tlp-e-come-lo-applica-questo-sito)
  * [La pagina pubblica riporta i nomi delle vittime di ransomware. È responsabile?](#la-pagina-pubblica-riporta-i-nomi-delle-vittime-di-ransomware-è-responsabile)
* [Dati e sorgenti](#dati-e-sorgenti)
  * [Da dove provengono i dati?](#da-dove-provengono-i-dati)
  * [Come fa la piattaforma a sapere che due nomi indicano lo stesso gruppo?](#come-fa-la-piattaforma-a-sapere-che-due-nomi-indicano-lo-stesso-gruppo)
  * [Perché la valutazione 6 x 6 e non la 4 x 4 UNODC usata dagli altri strumenti SOsintOps?](#perché-la-valutazione-6-x-6-e-non-la-4-x-4-unodc-usata-dagli-altri-strumenti-sosintops)
  * [Quanto sono aggiornati i dati?](#quanto-sono-aggiornati-i-dati)
  * [Una voce vittima è errata o andrebbe rimossa. Potete correggerla?](#una-voce-vittima-è-errata-o-andrebbe-rimossa-potete-correggerla)
  * [Che cos'è il monitor di salute delle sorgenti?](#che-cosè-il-monitor-di-salute-delle-sorgenti)
  * [Il sito traccia i suoi visitatori?](#il-sito-traccia-i-suoi-visitatori)
* [Uso della UI](#uso-della-ui)
  * [Che differenza c'è tra "Victims" e "Cyberattacks"?](#che-differenza-cè-tra-victims-e-cyberattacks)
  * [Cosa mostrano le pagine degli avversari?](#cosa-mostrano-le-pagine-degli-avversari)
  * [Che cos'è la pagina della matrice ATT&CK?](#che-cosè-la-pagina-della-matrice-attck)
  * [Come funziona la watchlist?](#come-funziona-la-watchlist)
  * [Cosa sono Articles e Campaigns?](#cosa-sono-articles-e-campaigns)
  * [Posso esportare i dati?](#posso-esportare-i-dati)
* [La pipeline AI](#la-pipeline-ai)
  * [Cosa fa davvero l'AI?](#cosa-fa-davvero-lai)
  * [Quali provider LLM usa?](#quali-provider-llm-usa)
  * [I miei dati possono finire in un LLM in cloud?](#i-miei-dati-possono-finire-in-un-llm-in-cloud)
  * [Cosa impedisce all'AI di spendere denaro?](#cosa-impedisce-allai-di-spendere-denaro)
  * [L'AI può allucinare un indicatore dentro il database?](#lai-può-allucinare-un-indicatore-dentro-il-database)
* [REST API](#rest-api)
  * [Esiste una API?](#esiste-una-api)
  * [Come autentico le chiamate API?](#come-autentico-le-chiamate-api)
  * [C'è un rate limit?](#cè-un-rate-limit)
* [Self-hosting](#self-hosting)
  * [Cosa mi serve per eseguire una mia istanza?](#cosa-mi-serve-per-eseguire-una-mia-istanza)
  * [Come lo installo?](#come-lo-installo)
  * [Come viene creato il primo account admin?](#come-viene-creato-il-primo-account-admin)
  * [Come applico le migrazioni del database?](#come-applico-le-migrazioni-del-database)
  * [Come faccio il backup del database?](#come-faccio-il-backup-del-database)
  * [Quali variabili d'ambiente contano di più?](#quali-variabili-dambiente-contano-di-più)
  * [Posso esporre la mia istanza su internet?](#posso-esporre-la-mia-istanza-su-internet)
  * [Posso disabilitare una sorgente dati?](#posso-disabilitare-una-sorgente-dati)
* [Sicurezza](#sicurezza)
  * [Come è implementata l'autenticazione?](#come-è-implementata-lautenticazione)
  * [Cosa viene registrato nel log attività?](#cosa-viene-registrato-nel-log-attività)
  * [Chi può leggere il log attività?](#chi-può-leggere-il-log-attività)
  * [Come segnalo una vulnerabilità di sicurezza?](#come-segnalo-una-vulnerabilità-di-sicurezza)
  * [La mia password è conservata in modo sicuro?](#la-mia-password-è-conservata-in-modo-sicuro)
* [Risoluzione dei problemi](#risoluzione-dei-problemi)
  * [Non riesco ad accedere.](#non-riesco-ad-accedere)
  * [L'accesso riesce ma vengo subito disconnesso.](#laccesso-riesce-ma-vengo-subito-disconnesso)
  * [L'amministratore è bloccato e non esiste un altro admin.](#lamministratore-è-bloccato-e-non-esiste-un-altro-admin)
  * [Le mappe sono vuote.](#le-mappe-sono-vuote)
  * [La pagina FAQ o Changelog è vuota.](#la-pagina-faq-o-changelog-è-vuota)
  * [`docker compose up` fallisce con un errore sulla secret key.](#docker-compose-up-fallisce-con-un-errore-sulla-secret-key)
  * [Una migrazione fallisce durante l'upgrade.](#una-migrazione-fallisce-durante-lupgrade)
  * [Lo scheduler non sta ingerendo dati.](#lo-scheduler-non-sta-ingerendo-dati)
* [Progetto e licenza](#progetto-e-licenza)
  * [Quale licenza usa Elementary CTI?](#quale-licenza-usa-elementary-cti)
  * [Posso contribuire?](#posso-contribuire)
  * [Dov'è la roadmap?](#dovè-la-roadmap)
  * [Ci sono progetti SOsintOps correlati?](#ci-sono-progetti-sosintops-correlati)
  * [Qualche Large Language Model è stato indebitamente stressato durante lo sviluppo?](#qualche-large-language-model-è-stato-indebitamente-stressato-durante-lo-sviluppo)

## Il progetto

### Che cos'è Elementary CTI?

Elementary CTI è un aggregatore multi-sorgente di threat intelligence sul
ransomware. Raccoglie dati su vittime e attacchi informatici da fonti
pubbliche di tracciamento del ransomware, li arricchisce con le TTP di [MITRE
ATT&CK](https://attack.mitre.org/), con intelligence sui pagamenti in Bitcoin e con dati operativi, e
presenta tutto attraverso una UI web pensata per l'indagine degli analisti.

### Perché si chiama "Elementary"?

Il nome rende omaggio alla serie TV *Elementary* e al suo Sherlock Holmes:
un consulente che trasforma osservazioni sparse in deduzioni. Il codice è
pieno di citazioni dalla serie. Il nome in codice originale del progetto era
**Pestilentia**, e il package Python si chiama ancora `pestilentia/` — è
cambiato solo il brand del prodotto.

### È un prodotto commerciale?

No. Elementary CTI è un progetto open source personale, rilasciato con
licenza AGPL-3.0. Non c'è un'azienda dietro, non ci sono piani a pagamento
né SLA.

### A chi è rivolto?

Ad analisti di threat intelligence, team SOC, ricercatori e a chiunque
voglia una vista self-hosted e verificabile dell'attività ransomware senza
dipendere da una piattaforma commerciale.

## Accesso e account

### Perché vedo solo una piccola dashboard e un riquadro di accesso?

Non hai effettuato l'accesso. I visitatori anonimi vedono una panoramica
pubblica limitata agli ultimi 30 giorni di attività da fonti pubbliche.
Tutto il resto — storico completo, profili degli avversari, mappe,
watchlist, la pipeline AI — richiede un account.

### Come ottengo un account?

Gli account sono creati da un amministratore dell'istanza che stai
visitando. Non esiste auto-registrazione. Contatta l'operatore
dell'istanza.

### Quali sono i ruoli?

| Ruolo | Cosa sblocca |
|---|---|
| `user` | Accesso in lettura all'intero dataset: dashboard, vittime, avversari, attacchi informatici, mappa, articoli, campagne, ricerca |
| `analyst` | Tutto ciò che ha `user`, più le superfici di analisi (analisi IP, code di revisione, azioni AI) man mano che vengono rilasciate |
| `admin` | Tutto, più la gestione utenti, l'attivazione/disattivazione delle sorgenti e le chiavi API di servizio nelle impostazioni |

### Come effettuo l'accesso?

1. Trova il riquadro di accesso nella barra laterale sinistra, oppure apri `/login`.
2. Inserisci nome utente e password.
3. Seleziona **Sign in**.

### Quanto dura una sessione?

Una sessione termina 12 ore dopo l'accesso, oppure dopo 2 ore di
inattività, a seconda di quale limite arriva prima. Effettua di nuovo
l'accesso per continuare.

### Ho sbagliato la password diverse volte e ora sono bloccato. Cosa faccio?

Aspetta. Dopo cinque tentativi falliti, la coppia account-indirizzo viene
bloccata, partendo da 30 secondi e raddoppiando fino a 15 minuti. Il blocco
si azzera da solo. Se hai dimenticato la password, chiedi a un
amministratore di reimpostarla.

### Posso cambiare la password?

Sì:

1. Apri **Settings** nella barra laterale.
2. In **Change password**, inserisci la password attuale e quella nuova
   (minimo 10 caratteri), due volte.
3. Seleziona **Update password**. Resti connesso.

### Perché sono stato disconnesso senza preavviso?

Tre cause comuni: la sessione ha superato il limite di 12 ore, sei rimasto
inattivo per più di 2 ore, oppure un amministratore ha disabilitato il tuo
account. Gli account disabilitati vengono disconnessi alla richiesta
successiva.

## La dashboard pubblica e il TLP

### Cosa mostra esattamente la dashboard pubblica?

Contatori aggregati, una timeline giornaliera delle vittime, i nomi delle
vittime recenti e i gruppi più attivi — il tutto limitato agli ultimi 30
giorni e costruito solo da fonti pubbliche di tracciamento. Non ci sono
collegamenti verso il dataset completo.

### Che cos'è il TLP e come lo applica questo sito?

Il TLP ([Traffic Light Protocol](https://www.first.org/tlp/), versione 2.0) indica quanto ampiamente un'informazione
può essere condivisa. Elementary CTI marca ogni articolo ingerito con un
livello TLP. La dashboard pubblica non interroga mai i contenuti marcati
TLP, quindi nulla al di sopra di TLP:CLEAR può comparirvi — per
costruzione, non per filtro. La stessa disciplina regola quali contenuti
possono raggiungere un LLM in cloud.

### La pagina pubblica riporta i nomi delle vittime di ransomware. È responsabile?

I nomi provengono da fonti pubbliche di tracciamento del ransomware; le
vittime sono già state pubblicate dai criminali e indicizzate dai tracker.
Elementary CTI ripubblica solo ciò che è già pubblico, limitato a 30
giorni, senza amplificare i dettagli (niente URL delle rivendicazioni,
niente screenshot, niente drill-down).

## Dati e sorgenti

### Da dove provengono i dati?

Dati strutturati: ransomware.live (vittime, gruppi, attacchi), MITRE
ATT&CK (TTP), Ransomwhere (pagamenti in Bitcoin) e deepdarkCTI (dati
operativi: siti onion, canali Telegram/Tox). Articoli: 12 feed RSS curati
da laboratori di ricerca di vendor e testate di settore (CISA, The DFIR
Report, Unit 42, Talos, Microsoft, SentinelLABS, BleepingComputer e altri).

### Come fa la piattaforma a sapere che due nomi indicano lo stesso gruppo?

Lo chiede a un catalogo invece di deciderlo da sé. Lo stesso avversario è
quasi sempre conosciuto sotto più nomi insieme, perché ogni casa di ricerca
battezza ciò che trova secondo il proprio schema: una chiama Panda un gruppo
cinese, un'altra lo chiama Typhoon, una terza gli assegna un numero finché
non è abbastanza sicura da dargli un nome. Leggere un nome e indovinare il
resto fonde gruppi che non sono lo stesso, ed è l'unico errore che a valle
nessuno può più vedere.

Perciò un alias viene registrato solo dove un catalogo pubblicato lo elenca,
e la registrazione conserva quale catalogo lo dice. I cataloghi usati sono
gli intrusion set di MITRE ATT&CK, la galassia threat-actor del progetto
MISP e la tabella che Microsoft pubblica dei propri nomi con quelli usati
dagli altri vendor. Tutti e tre sono pubblici, versionati e verificabili da
chiunque abbia lo stesso file, ed è questo a rendere un alias una prova
invece che un'opinione. Dove nessun catalogo conosce il nome, la piattaforma
lo dichiara e lascia la domanda a un analista invece di inventare una
risposta.

### Perché la valutazione 6 x 6 e non la 4 x 4 UNODC usata dagli altri strumenti SOsintOps?

Ogni risultato proposto dalla pipeline AI viene valutato su due assi separati prima di poter arricchire il database: quanto è affidabile la fonte e quanto è valida l'informazione. Restano separati perché, come dice il [*Criminal Intelligence: Manual for Analysts*](https://www.unodc.org/documents/organized-crime/Law-Enforcement/Criminal_Intelligence_for_Analysts.pdf) dell'UNODC, la fonte va valutata separatamente dall'informazione. Gli altri strumenti SOsintOps usano il sistema 4 x 4 di quel manuale; Elementary CTI mantiene di proposito il sistema 6 x 6 (fonte da A a F, informazione da 1 a 6).

Il motivo è ciò che viene valutato. L'asse dell'informazione del 4 x 4 chiede se la fonte conosceva l'informazione di persona, e dà un voto più basso al sentito dire: una domanda pensata per una fonte umana, a cui un articolo RSS o un record di un leak site non può rispondere. L'asse dell'informazione del 6 x 6 chiede se un elemento è confermato da altre fonti, coerente in sé e non contraddetto, e questi sono predicati che la piattaforma può calcolare sui dati che già possiede. Sull'asse della fonte il 6 x 6 può dire "abbastanza affidabile" (C), che si adatta a una testata di settore che riporta con competenza le ricerche altrui, mentre la C del 4 x 4 significa "nella maggior parte dei casi si è dimostrata inaffidabile".

Ne seguono due regole. F sull'asse della fonte e 6 su quello dell'informazione significano che alla domanda non si è potuto rispondere, e un risultato che non si può valutare non arricchisce mai il database in automatico: passa a un analista. E l'eccezione resta dentro questo strumento: quando un elemento valutato qui entra in un report di caso scritto con gli altri strumenti SOsintOps, si converte il voto della fonte e si rivaluta l'informazione con le domande del 4 x 4, come spiegato in [Intelligence Field Notes](https://github.com/SOsintOps/intelligence-field-notes/blob/main/docs/source-evaluation.md#one-exception-machine-graded-cti-feeds).

### Quanto sono aggiornati i dati?

Lo scheduler interroga le sorgenti ogni 4 ore. Gli arricchimenti MITRE,
Ransomwhere e deepdarkCTI si aggiornano settimanalmente. L'intestazione
della dashboard mostra l'ora dell'ultimo aggiornamento.

### Una voce vittima è errata o andrebbe rimossa. Potete correggerla?

Elementary CTI rispecchia le fonti a monte; non origina rivendicazioni. Le
correzioni devono avvenire alla fonte (per esempio, ransomware.live).
Quando il record a monte cambia, il ciclo successivo dello scheduler lo
recepisce.

### Che cos'è il monitor di salute delle sorgenti?

Ogni ciclo verifica ciascuna sorgente con un probe HTTP e di formato. Lo
stato compare nella pagina Pipeline. Un sentinel settimanale separato
rileva l'impronta della *forma* di ogni contratto API a monte e segnala le
derive prima che interrompano l'ingestion.

### Il sito traccia i suoi visitatori?

Le visite anonime alle pagine pubbliche non vengono registrate. L'attività
degli utenti autenticati viene registrata (pagina, ora, indirizzo) per fini
di audit di sicurezza — vedi la sezione Sicurezza.

## Uso della UI

### Che differenza c'è tra "Victims" e "Cyberattacks"?

Le vittime sono organizzazioni rivendicate sui leak site del ransomware.
Gli attacchi informatici sono record di incidenti (notifiche di violazione,
comunicazioni pubbliche) tracciati separatamente, con date e descrizioni
proprie.

### Cosa mostrano le pagine degli avversari?

Ogni pagina di gruppo combina la descrizione di ransomware.live, il profilo
MITRE ATT&CK completo (alias, TTP, software), i canali operativi di
deepdarkCTI, le transazioni BTC, l'attribuzione geografica e uno storico
delle vittime con i trend.

### Che cos'è la pagina della matrice ATT&CK?

`/attack` mostra quali tecniche MITRE ATT&CK sono coperte dai gruppi
presenti nel database, ordinate per kill chain. Una cella vuota significa
"non osservata nei nostri dati", non "non usata da nessuno".

### Come funziona la watchlist?

Aggiungi i nomi delle organizzazioni che ti interessano (la tua azienda,
fornitori, clienti). Ogni nuova vittima viene confrontata con la watchlist
tramite fuzzy matching; le corrispondenze generano avvisi con livelli di
gravità, visibili nella UI e inoltrabili via webhook.

### Cosa sono Articles e Campaigns?

Articles è la lista di lettura che la pipeline AI ingerisce: voci
deduplicate dai feed curati, con marcature TLP e flag di priorità guidati
dalla tua watchlist. Campaigns raggruppa gli articoli correlati con
embedding locali, così un incidente coperto da cinque testate si legge come
un'unica storia.

### Posso esportare i dati?

Sì. Ogni avversario offre l'export di un bundle [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
(`/api/v1/groups/{id}/stix`), pronto per MISP o OpenCTI. La REST API serve
JSON per tutto il resto.

## La pipeline AI

### Cosa fa davvero l'AI?

Oggi: ingestion degli articoli, deduplicazione, clustering delle campagne e
un livello di triage LLM con routing. In sviluppo: una pipeline di
estrazione completa che trasforma gli articoli in intelligence strutturata
sugli avversari, ancorata alle fonti, con una coda di revisione per gli
analisti.

### Quali provider LLM usa?

Un router agnostico rispetto al provider decide per ogni chiamata. Il
provider cloud attualmente preferito è il free tier di NVIDIA NIM (Llama
3.1 8B per il triage, Llama 3.3 70B per l'analisi); i modelli Anthropic
Claude sono registrati per quando esisterà una chiave finanziata; è
previsto un fallback locale con Ollama.

### I miei dati possono finire in un LLM in cloud?

I contenuti pari o inferiori al tetto TLP configurato
(`PEST_AI_TLP_CLOUD_MAX`, default `green`) possono raggiungere un provider
cloud. Tutto ciò che sta sopra resta in locale o attende un umano. Ogni
chiamata LLM viene registrata con costo e conteggio dei token.

### Cosa impedisce all'AI di spendere denaro?

Tre tetti rigidi: limite di token per articolo, budget giornaliero, budget
mensile. All'80% del budget giornaliero il router degrada al tier
economico; al 100% rifiuta. Tutti i limiti sono configurazione, non
abitudini.

### L'AI può allucinare un indicatore dentro il database?

Il design dell'estrazione (in sviluppo) richiede che ogni indicatore sia
ancorato testualmente nell'articolo di origine e che ogni affermazione sia
etichettata come osservata o dedotta; l'output non verificabile viene
rifiutato o messo in attesa di revisione umana, mai unito silenziosamente.

## REST API

### Esiste una API?

Sì: endpoint JSON in sola lettura sotto `/api/v1/` (statistiche, vittime,
gruppi, attacchi informatici, dati per la mappa, timeline, export STIX). La
documentazione interattiva è su `/docs` dopo l'accesso.

### Come autentico le chiamate API?

L'API usa lo stesso cookie di sessione della UI. Effettua l'accesso tramite
`/login`, poi invia il cookie `pest_session` con ogni richiesta. Le
chiamate non autenticate ricevono `401`. L'accesso API basato su token è
nella roadmap.

### C'è un rate limit?

Oggi non per endpoint. I tentativi di accesso sono soggetti a rate limit.
Sii ragionevole: di solito questo gira su un Raspberry Pi, non su una CDN.

## Self-hosting

### Cosa mi serve per eseguire una mia istanza?

- Docker e Docker Compose.
- 2 GB di RAM e qualche GB di disco. Un Raspberry Pi 5 esegue l'istanza di
  riferimento.
- Opzionale: un database PostgreSQL (il default è SQLite per lo sviluppo).

### Come lo installo?

1. Clona il repository.
2. Copia `.env.example` in `.env`.
3. Imposta `PEST_SECRET_KEY` a un valore casuale. Generane uno con
   `python -c "import secrets; print(secrets.token_hex(32))"`.
4. Imposta `PEST_AUTH_USER` e `PEST_AUTH_PASS`. Questi valori inizializzano
   il primo account admin.
5. Esegui `docker compose up -d --build`.
6. Apri `http://localhost:8000` ed effettua l'accesso.

### Come viene creato il primo account admin?

Al primo avvio, se la tabella `users` è vuota e `PEST_AUTH_USER` e
`PEST_AUTH_PASS` sono impostate, l'applicazione crea quell'account con il
ruolo `admin`. Da lì in poi, gestisci gli account in **Settings → Users**
(creazione, disabilitazione, eliminazione, cambio ruolo, reset password —
l'ultimo admin attivo è protetto dal blocco accidentale). Le variabili non
vengono più lette una volta che esistono utenti.

### Come applico le migrazioni del database?

Esegui `alembic upgrade head` con `PEST_DB_URL` che punta al tuo database.
Le migrazioni sono additive e supportano il downgrade. Fai sempre prima un
backup.

### Come faccio il backup del database?

Per PostgreSQL: `pg_dump` pianificato. Il deployment di riferimento invia
un dump giornaliero a un branch git privato off-site tramite un timer
systemd. Per SQLite: copia il file del database ad applicazione ferma.

### Quali variabili d'ambiente contano di più?

| Variabile | Scopo |
|---|---|
| `PEST_DB_URL` | Stringa di connessione al database |
| `PEST_SECRET_KEY` | Firma sessioni e token CSRF. Obbligatoria in produzione |
| `PEST_AUTH_USER` / `PEST_AUTH_PASS` | Seed di bootstrap per il primo admin |
| `PEST_COOKIE_SECURE` | `true` dietro TLS (default); `false` solo per uso in LAN con HTTP in chiaro |
| `PEST_ACTIVITY_RETENTION_DAYS` | Per quanto tempo vengono conservate le righe del log attività (default 90) |
| `PEST_POLL_INTERVAL_HOURS` | Ciclo dello scheduler (default 4) |
| `PEST_AI_TLP_CLOUD_MAX` | Livello TLP massimo ammesso verso un LLM in cloud |
| `PEST_AI_DAILY_BUDGET_USD` / `PEST_AI_MONTHLY_BUDGET_USD` | Tetti rigidi di spesa LLM |
| `PEST_AI_NVIDIA_API_KEY` | Chiave NVIDIA NIM per la pipeline AI |

`.env.example` documenta l'elenco completo.

### Posso esporre la mia istanza su internet?

Solo dietro un reverse proxy TLS, e solo dopo aver rivisto la checklist di
sicurezza. Il deployment di riferimento usa Caddy per la terminazione TLS e
mantiene non pubblicata la porta dell'app. Imposta
`PEST_COOKIE_SECURE=true` (il default) dietro TLS. Un audit OWASP Top 10
condiziona l'esposizione dello stesso deployment di riferimento.

### Posso disabilitare una sorgente dati?

Sì, come amministratore: **Settings → Sources** elenca sorgenti primarie,
arricchimenti e feed di articoli, ciascuno con un controllo di
abilitazione/disabilitazione. Una sorgente disabilitata viene saltata dal
ciclo successivo dello scheduler. Ogni modifica viene registrata nel log di
audit amministrativo.

## Sicurezza

### Come è implementata l'autenticazione?

Account lato server con hashing delle password argon2id, cookie di sessione
firmati (HttpOnly, SameSite=Lax, Secure dietro TLS) con scadenza assoluta
di 12 ore e di inattività di 2 ore, rotazione della sessione a ogni
accesso, token CSRF su ogni form e backoff esponenziale sui tentativi di
accesso.

### Cosa viene registrato nel log attività?

Ogni richiesta autenticata (chi, quale pagina, quando, da quale indirizzo),
ogni accesso fallito con il nome utente tentato, ogni blocco e ogni
richiesta negata. La navigazione anonima delle pagine pubbliche non viene
registrata. Le righe vengono eliminate dopo un periodo di conservazione
configurabile (default 90 giorni).

### Chi può leggere il log attività?

Gli amministratori, in **Settings → Activity**: filtri per tipo di evento,
nome utente e finestra temporale, con contatori per accessi falliti,
blocchi e richieste negate. Le righe del log non contengono mai password né
token di sessione.

### Come segnalo una vulnerabilità di sicurezza?

Usa la segnalazione privata delle vulnerabilità di GitHub sul repository
(Security → Report a vulnerability). Non aprire una issue pubblica. Vedi
`SECURITY.md`.

### La mia password è conservata in modo sicuro?

Le password sono sottoposte a hashing con argon2id (l'attuale
raccomandazione OWASP) e non vengono mai registrate nei log, mostrate o
inviate da nessuna parte. Nessuno, amministratore incluso, può leggere la
tua password.

## Risoluzione dei problemi

### Non riesco ad accedere.

1. Controlla il nome utente. È in minuscolo.
2. Controlla la password. Il messaggio di errore è lo stesso per nome
   utente errato e password errata.
3. Aspetta 15 minuti se hai fatto molti tentativi. Il blocco si azzera da
   solo.
4. Chiedi a un amministratore di verificare che il tuo account esista e sia
   abilitato.

### L'accesso riesce ma vengo subito disconnesso.

Il tuo browser ha rifiutato il cookie di sessione. Se l'istanza gira su
HTTP in chiaro (senza TLS), l'operatore deve impostare
`PEST_COOKIE_SECURE=false`. Dietro HTTPS, verifica che il browser accetti i
cookie per il sito.

### L'amministratore è bloccato e non esiste un altro admin.

1. Ferma l'applicazione.
2. Elimina tutte le righe dalla tabella `users`.
3. Verifica `PEST_AUTH_USER` e `PEST_AUTH_PASS` in `.env`.
4. Avvia l'applicazione. Il bootstrap ricrea l'account admin.

Attenzione: questa procedura rimuove tutti gli account. Usala solo per il
ripristino.

### Le mappe sono vuote.

Controlla la console del browser. Se un file Plotly non si carica, al
deployment mancano gli asset statici vendorizzati — ricostruisci
l'immagine. Tutti gli asset sono serviti in locale; l'app non scarica mai
da una CDN, quindi un ad-blocker non è la causa.

### La pagina FAQ o Changelog è vuota.

L'immagine del deployment è stata costruita senza i file markdown.
Ricostruisci l'immagine; il Dockerfile deve copiare `CHANGELOG.md` e
`docs/FAQ.md`.

### `docker compose up` fallisce con un errore sulla secret key.

Imposta `PEST_SECRET_KEY` in `.env` a un valore diverso dal placeholder.
Generane uno con `python -c "import secrets; print(secrets.token_hex(32))"`.

### Una migrazione fallisce durante l'upgrade.

1. Leggi l'errore. La maggior parte dei fallimenti indica tabella e
   revisione.
2. Ripristina il backup del database.
3. Apri una issue con il testo dell'errore e la tua revisione
   (`alembic current`).

### Lo scheduler non sta ingerendo dati.

1. Apri la pagina Pipeline e controlla gli indicatori di salute delle
   sorgenti.
2. Controlla i log del container dello scheduler:
   `docker logs <project>-scheduler-1 --since 1h`.
3. Una sorgente in errore riprova al ciclo successivo. Due fallimenti di
   formato consecutivi di solito significano che l'API a monte ha cambiato
   forma — controlla il report del contract sentinel.

## Progetto e licenza

### Quale licenza usa Elementary CTI?

AGPL-3.0-or-later. Se esegui una versione modificata come servizio di rete,
devi offrire il codice sorgente modificato ai suoi utenti.

### Posso contribuire?

Sì. Apri una issue o una pull request su GitHub. Il repository include
template per le issue, un template di PR con i quality gate e le linee
guida per i contributi.

### Dov'è la roadmap?

Ad alto livello: `README.md` e la pagina `/guide`. I documenti di progettazione dettagliati e i piani di lavoro sono conservati fuori da questa distribuzione; le decisioni che contano per gli utenti sono spiegate in questa FAQ e in `CHANGELOG.md` (consultabile su `/changelog`).

### Ci sono progetti SOsintOps correlati?

Sì. Elementary CTI è uno dei diversi strumenti open source pubblicati da [SOsintOps](https://github.com/SOsintOps), che condividono un unico metodo.

- **[Intelligence Field Notes](https://github.com/SOsintOps/intelligence-field-notes)** - Le note di metodo dietro tutti gli strumenti (in inglese): valutazione delle fonti, linguaggio estimativo (i termini di probabilità di [ICD 203](https://www.dni.gov/files/documents/ICD/ICD-203.pdf) usati dalla pipeline AI), tecniche analitiche come l'Analysis of Competing Hypotheses di Heuer, da [*Psychology of Intelligence Analysis*](https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/), e la scrittura dei report con la conclusione in apertura, secondo lo [*Style Manual & Writers Guide*](https://irp.fas.org/cia/product/style.pdf) della CIA.
- **[Aethelburg](https://github.com/SOsintOps/Aethelburg-project)** - Analizza i dati di Companies House (Regno Unito) per individuare società schermo e strutture societarie anomale: il passo successivo quando una vittima citata su un leak site va profilata in un registro delle imprese.
- **[Quaesitor](https://github.com/SOsintOps/quaesitor)** - Un grafo di caso locale con il metodo di link analysis UNODC, per ricostruire il quadro attorno a un attore o a un incidente una volta uscito dal feed.
- **[Acta Diurna](https://github.com/SOsintOps/acta-diurna)** - Una dashboard che monitora le notizie sulle operazioni delle forze dell'ordine in Italia: lo stesso problema di monitoraggio dei feed in un altro ambito.
- **[Codex Machinae](https://github.com/SOsintOps/codex-machinae)** - Il playbook di sviluppo con cui è costruito questo progetto; il suo modulo di classificazione copre ATT&CK, STIX e TLP per gli strumenti di intelligence.
- **[Exploratores](https://github.com/SOsintOps/Exploratores)**, **[Argos](https://github.com/SOsintOps/Argos)** e **[Speculator](https://github.com/SOsintOps/Speculator-Project)** - Un toolkit OSINT nel browser e due postazioni OSINT, per l'indagine manuale (domini, società, account) che segue un risultato.
- **[Il Conclave](https://github.com/SOsintOps/il-conclave)** - Una skill per Claude Code che applica ACH, premortem e altre tecniche strutturate a una domanda, utile quando un'attribuzione è contestata.

### Qualche Large Language Model è stato indebitamente stressato durante lo sviluppo?

Diversi, ampiamente, e lo rifarebbero — anche se uno di loro sostiene che
la grafia corretta sia "Watson".
