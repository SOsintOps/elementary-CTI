# UI language catalog (EN default, IT via the sidebar toggle).
# Only descriptive strings live here — page intros, chrome labels, notices.
# Data content is source-language and never translated. Keys are stable ids;
# English is the fallback for any missing translation.
from __future__ import annotations

DEFAULT_LANG = "en"
SUPPORTED_LANGS = ("en", "it")

STRINGS: dict[str, dict[str, str]] = {
    "intro_dashboard": {
        "en": (
            "Real-time overview of ransomware threats. The counters aggregate victims, "
            "adversary groups, cyberattacks and affected countries across all active "
            "sources. Recent victims are filterable by period (7 days, 1 month, 1 year). "
            'The "Sources" counter includes both primary data feeds and enrichment '
            'sources (MITRE, Ransomwhere, deepdarkCTI). Click "Refresh Now" to force a '
            "manual update of every source."
        ),
        "it": (
            "Panoramica in tempo reale delle minacce ransomware. I contatori aggregano "
            "vittime, gruppi avversari, cyberattacchi e paesi coinvolti da tutte le fonti "
            "attive. Le vittime recenti sono filtrabili per periodo (7 giorni, 1 mese, 1 "
            'anno). Il contatore "Sources" include sia i feed dati primari sia le fonti '
            'di arricchimento (MITRE, Ransomwhere, deepdarkCTI). Clicca "Refresh Now" per '
            "forzare un aggiornamento manuale di tutte le fonti."
        ),
    },
    "intro_dashboard_public": {
        "en": (
            "Public overview built from open ransomware tracking sources. The numbers and "
            "names below cover the last 30 days only. Sign in to access the full dataset: "
            "complete history, adversary profiles, MITRE ATT&CK coverage, BTC payment "
            "intelligence, maps, watchlists, and the AI article pipeline."
        ),
        "it": (
            "Panoramica pubblica costruita da fonti aperte di tracciamento ransomware. I "
            "numeri e i nomi qui sotto coprono solo gli ultimi 30 giorni. Accedi per "
            "sbloccare il dataset completo: storia integrale, profili degli avversari, "
            "copertura MITRE ATT&CK, intelligence sui pagamenti BTC, mappe, watchlist e "
            "la pipeline AI degli articoli."
        ),
    },
    "intro_victims": {
        "en": (
            "Complete register of organizations hit by ransomware, collected from threat "
            "intelligence feeds. Filter by name or domain, responsible group and country. "
            "Click a victim for the full details: attack date, attributed group, linked "
            "organizations and any duplicate reports from different sources. Duplicates "
            "are identified by fuzzy matching on name and domain."
        ),
        "it": (
            "Registro completo delle organizzazioni colpite da ransomware, raccolte dai "
            "feed di threat intelligence. Filtra per nome o dominio, gruppo responsabile "
            "e paese. Clicca su una vittima per visualizzare i dettagli completi: data "
            "dell'attacco, gruppo attribuito, organizzazioni collegate e eventuali "
            "segnalazioni duplicate da fonti diverse. I duplicati vengono identificati "
            "tramite matching fuzzy su nome e dominio."
        ),
    },
    "intro_groups": {
        "en": (
            "Catalog of the tracked ransomware and hacktivist groups. Each card shows the "
            "generated avatar, the country of origin (flag), the victim count and a short "
            "description. Click a group for the full profile: overview (Diamond Model, "
            "Pyramid of Pain), infrastructure (.onion sites, BTC wallets, communication "
            "channels), arsenal (software tools), TTPs (MITRE ATT&CK techniques), victim "
            "list and references (reports, CISA alerts)."
        ),
        "it": (
            "Catalogo dei gruppi ransomware e hacktivisti monitorati. Ogni scheda mostra "
            "l'avatar generato, il paese di origine (bandiera), il conteggio vittime e "
            "una breve descrizione. Clicca su un gruppo per accedere al profilo completo: "
            "panoramica (Diamond Model, Pyramid of Pain), infrastruttura (siti .onion, "
            "wallet BTC, canali comunicazione), arsenale (strumenti software), TTPs "
            "(tecniche MITRE ATT&CK), lista vittime e riferimenti (report, alert CISA)."
        ),
    },
    "intro_cyberattacks": {
        "en": (
            "List of attack events recorded from threat intelligence feeds. A cyberattack "
            "represents a single offensive action: the same victim can appear in multiple "
            "attacks if hit repeatedly or by different groups. Filter by victim name, "
            "notice title or country. Each row links to the corresponding victim detail."
        ),
        "it": (
            "Elenco degli eventi di attacco registrati dai feed di threat intelligence. "
            "Un cyberattacco rappresenta una singola azione offensiva: la stessa vittima "
            "può comparire in attacchi multipli se colpita ripetutamente o da gruppi "
            "diversi. Filtra per nome vittima, titolo del comunicato o paese. Ogni riga è "
            "collegata al dettaglio della vittima corrispondente."
        ),
    },
    "intro_map": {
        "en": (
            "Choropleth map of the global distribution of ransomware victims. The color "
            "scale (yellow-orange-red) uses quantile binning to highlight differences "
            "even with skewed distributions. Use the time filters to analyze how threats "
            "evolve. Hover over a country for the exact count, click to filter the victim "
            "list to that country."
        ),
        "it": (
            "Mappa coropletica della distribuzione globale delle vittime di ransomware. "
            "La scala cromatica (giallo-arancione-rosso) usa un binning quantile per "
            "evidenziare le differenze anche con distribuzioni sbilanciate. Usa i filtri "
            "temporali per analizzare l'evoluzione delle minacce. Passa il mouse su un "
            "paese per il conteggio esatto, clicca per filtrare la lista vittime per quel "
            "paese."
        ),
    },
    "intro_btc": {
        "en": (
            "Explore the Bitcoin addresses associated with ransomware groups. Data comes "
            "from Ransomwhere and tracks victim payments to adversary-controlled wallets. "
            "Search an address (even partial) to find the associated group, transaction "
            "volume and USD value. Without an active search, the 20 addresses with the "
            "highest BTC volume are shown. Addresses link to blockchain.com for on-chain "
            "verification."
        ),
        "it": (
            "Esplora gli indirizzi Bitcoin associati ai gruppi ransomware. I dati "
            "provengono da Ransomwhere e tracciano i pagamenti delle vittime verso wallet "
            "controllati dagli avversari. Cerca un indirizzo (anche parziale) per trovare "
            "il gruppo associato, il volume delle transazioni e il controvalore in USD. "
            "Senza ricerca attiva, vengono mostrati i 20 indirizzi con il maggior volume "
            "BTC. Gli indirizzi sono collegati a blockchain.com per la verifica on-chain."
        ),
    },
    "intro_search": {
        "en": (
            "Global search across every entity on the platform. The query is matched "
            "simultaneously against victim names and domains, adversary group names and "
            "aliases, and cyberattack titles and names. The search is case-insensitive "
            "and supports partial matches. Results are grouped by category (max 20 per "
            "type). This search is also available from the box in the navigation sidebar."
        ),
        "it": (
            "Ricerca globale su tutte le entità della piattaforma. La query viene "
            "confrontata simultaneamente con: nomi e domini delle vittime, nomi e alias "
            "dei gruppi avversari, titoli e nomi nei cyberattacchi. La ricerca è "
            "case-insensitive e supporta corrispondenze parziali. I risultati sono "
            "raggruppati per categoria (max 20 per tipo). Questa ricerca è accessibile "
            "anche dalla casella nella barra di navigazione."
        ),
    },
    "intro_watchlist": {
        "en": (
            "Proactive monitoring of specific organizations. Add a target with the "
            "company name, domain and optional keywords. On every data update, the system "
            "compares new victims against the watchlist targets using fuzzy matching "
            "(configurable threshold, default 85%). On a match, an alert is raised and "
            "notifications go to the configured channels (log, webhook). Alerts can be "
            "marked as read individually or all at once."
        ),
        "it": (
            "Monitoraggio proattivo di organizzazioni specifiche. Aggiungi un target "
            "indicando il nome dell'azienda, il dominio e parole chiave opzionali. Ad "
            "ogni aggiornamento dati, il sistema confronta le nuove vittime con i target "
            "della watchlist usando un algoritmo di matching fuzzy (soglia configurabile, "
            "default 85%). Quando viene trovata una corrispondenza, viene generato un "
            "alert e le notifiche vengono inviate ai canali configurati (log, webhook). "
            "Gli alert possono essere contrassegnati come letti singolarmente o tutti in "
            "blocco."
        ),
    },
    "intro_articles": {
        "en": (
            "Raw corpus ingested from the curated CTI feeds, deduplicated by canonical "
            "URL and by near-duplicate (simhash). This page shows only what the fetcher "
            "stored: no extraction, no language-model output. Analysis (IOCs, TTPs, "
            "Diamond Model) arrives in the later stages of the ADR-006 pipeline."
        ),
        "it": (
            "Corpus grezzo ingerito dai feed CTI curati, deduplicato per URL canonico e "
            "per near-duplicate (simhash). Questa pagina mostra solo ciò che il fetcher "
            "ha salvato: nessuna estrazione, nessun output di modello linguistico. "
            "L'analisi (IOC, TTP, Diamond Model) arriva nelle fasi successive della "
            "pipeline ADR-006."
        ),
    },
    "intro_campaigns_head": {
        "en": (
            "Articles grouped by campaign: different reports describing the same "
            'incident. Distinct from dedup — simhash answers "is this the same '
            'article?", this answers "are these different articles about the same '
            'event?". Cosine similarity'
        ),
        "it": (
            "Articoli raggruppati per campagna: report diversi che descrivono lo stesso "
            'incidente. Diverso dal dedup — il simhash risponde "è lo stesso articolo?", '
            'questo risponde "sono articoli diversi sullo stesso fatto?". Similarità '
            "coseno"
        ),
    },
    "campaigns_on_embeddings": {
        "en": "on local embeddings (model2vec, 256 dim),",
        "it": "su embedding locali (model2vec, 256 dim),",
    },
    "campaigns_on_tfidf": {
        "en": "on TF-IDF,",
        "it": "su TF-IDF,",
    },
    "campaigns_threshold": {"en": "threshold", "it": "soglia"},
    "campaigns_known_limit": {
        "en": (
            "Known limitation. Similarity also groups reports that share a template while "
            "covering different incidents. Recurring columns from the same outlet (at "
            "least three entries with the same title pattern) are now excluded "
            "automatically, but same-genre articles can still cluster. Read a group as "
            '"candidates for the same campaign", not as an established fact.'
        ),
        "it": (
            "Limite noto. La similarità raggruppa anche report che condividono un "
            "template pur riguardando incidenti diversi. Le rubriche ricorrenti di una "
            "stessa testata (almeno tre uscite con lo stesso titolo-tipo) sono ora "
            "escluse automaticamente, ma articoli dello stesso genere restano "
            'accorpabili. Un gruppo va letto come "candidati alla stessa campagna", non '
            "come un fatto accertato."
        ),
    },
    "campaigns_on_the_fly": {
        "en": (
            "Computed on the fly: nothing is persisted, so the threshold stays adjustable "
            "without rewriting data."
        ),
        "it": (
            "Calcolato al volo: nulla è persistito, quindi la soglia resta regolabile "
            "senza riscrivere dati."
        ),
    },
    "intro_attack_head": {
        "en": (
            "MITRE ATT&CK coverage matrix: tactics are columns in kill-chain order, "
            "techniques are cells."
        ),
        "it": (
            "Matrice di copertura MITRE ATT&CK: le tattiche sono colonne in ordine di "
            "kill-chain, le tecniche sono celle."
        ),
    },
    "attack_scoped_to": {
        "en": "View restricted to",
        "it": "Vista ristretta a",
    },
    "attack_magnitude": {
        "en": (
            "Color intensity shows how many distinct adversaries use that technique — it "
            "is a magnitude scale, so a single hue, darker = more widespread."
        ),
        "it": (
            "L'intensità del colore indica quanti avversari distinti usano quella "
            "tecnica — è una scala di magnitudine, quindi una sola tinta, più scuro = "
            "più diffuso."
        ),
    },
    "attack_absence": {
        "en": (
            "It covers only what the sources explicitly attribute: a missing technique "
            'means "not observed in our data", not "not used".'
        ),
        "it": (
            "Copre solo ciò che le fonti attribuiscono esplicitamente: l'assenza di una "
            'tecnica significa "non osservata nei nostri dati", non "non usata".'
        ),
    },
    "intro_pipeline": {
        "en": (
            "Control panel for the collection and enrichment pipeline. Each source can "
            "be enabled or disabled individually with its toggle: disabled sources are "
            "skipped both by the automatic scheduler cycle and by manual refresh. The "
            "cards show the current state (Active, Backfilling, Disabled) and a health "
            'indicator (green/yellow/red) from the latest health check. The "Enrichment '
            'Sources" table reports the key metrics for each enrichment, while "Source '
            'Health" verifies reachability and data integrity of the external sources.'
        ),
        "it": (
            "Pannello di controllo della pipeline di raccolta e arricchimento dati. Ogni "
            "fonte può essere attivata o disattivata individualmente tramite il toggle: "
            "le fonti disabilitate vengono saltate sia dallo scheduler automatico sia "
            "dal refresh manuale. Le schede mostrano lo stato corrente (Active, "
            "Backfilling, Disabled) e un indicatore di salute (verde/giallo/rosso) "
            'basato sull\'ultimo health check. La tabella "Enrichment Sources" riporta '
            'le metriche chiave per ogni arricchimento, mentre "Source Health" verifica '
            "la raggiungibilità e l'integrità dei dati delle fonti esterne."
        ),
    },
    "nav_guide": {"en": "Guide", "it": "Guida"},
    "guide_lang_note": {
        "en": "This guide is currently available in Italian only. An English version is planned.",
        "it": "",
    },
    "aria_font_smaller": {"en": "Decrease font size", "it": "Riduci dimensione caratteri"},
    "aria_font_larger": {"en": "Increase font size", "it": "Aumenta dimensione caratteri"},
    "aria_theme_toggle": {"en": "Light/dark theme", "it": "Tema chiaro/scuro"},
    "cookie_lost_title": {"en": "Sign-in did not stick.", "it": "L'accesso non è rimasto attivo."},
    "cookie_lost_body": {
        "en": (
            "Your credentials were accepted, but this browser did not keep the session "
            "cookie, so you are still browsing anonymously. Common causes: cookies "
            "blocked for this site, or the instance runs on plain HTTP while the session "
            "cookie carries the Secure flag — the operator must set "
            "PEST_COOKIE_SECURE=false for HTTP deployments."
        ),
        "it": (
            "Le credenziali sono state accettate, ma questo browser non ha conservato il "
            "cookie di sessione, quindi stai ancora navigando in forma anonima. Cause "
            "comuni: cookie bloccati per questo sito, oppure istanza su HTTP puro con il "
            "cookie di sessione marcato Secure — l'operatore deve impostare "
            "PEST_COOKIE_SECURE=false per i deployment HTTP."
        ),
    },
}


def translate(key: str, lang: str) -> str:
    entry = STRINGS.get(key)
    if entry is None:
        return key
    return entry.get(lang) or entry.get(DEFAULT_LANG, key)
