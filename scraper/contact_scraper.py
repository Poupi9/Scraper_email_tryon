# file: contact_scraper.py
"""
Scraper 'contact-only' pour boutiques (Paris ou autre).
Visite uniquement Contact/FAQ/Legal et leurs enfants (profondeur limitée).
Respecte robots.txt par défaut. PEP8 + typing.

Usage rapide:
    python contact_scraper.py --urls-file urls.txt --verbose
    # ou éditez START_URLS ci-dessous.

Sortie:
    contacts.csv  (UTF-8, en-têtes)

⚠️ Pourquoi ces choix:
- On cible les pages où se trouvent réellement les emails pour réduire bruit/volume.
- On n'efface pas tous les espaces pour éviter les emails collés à 'Partager...' etc.
- On ignore plateformes sociales/Google Maps (quasi toutes bloquées/peu utiles).
"""

from __future__ import annotations

import argparse
import csv
import logging
import random
import re
import string
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import Deque, Dict, Iterable, Iterator, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse, urldefrag

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib import robotparser

# ----------------------- Entrée par défaut ----------------------- #

START_URLS: List[str] = [
    "http://www.lesouriremulticolore.com/", 
    "http://www.wedressfair.fr/"
]
URLS_TXT = Path("urls.txt")

# ----------------------- Constantes & Regex ---------------------- #

TARGET_KEYWORDS = (
    "contact", "contactez", "faq", "aide", "help", "support", "sav",
    "mentions", "legal", "légal", "legales", "légales",
    "cgv", "cgu", "terms", "privacy", "confidentialite", "confidentialité", "rgpd",
    "donnees-personnelles", "données-personnelles", "data-protection",
    "impressum",  # parfois présent
)

PAGE_TYPES = ("contact", "faq", "legal", "contact_child")

BLOCKED_HOST_PARTS = (
    "facebook.com", "instagram.com", "tiktok.com", "x.com", "twitter.com",
    "linkedin.com", "google.", "youtube.com", "youtu.be", "pinterest.", "snapchat.com",
)

SKIP_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".ico",
    ".css", ".js", ".json", ".xml", ".rss", ".atom", ".webmanifest",
}

EMAIL_REGEX = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_FR_REGEX = re.compile(r"(?:\+33\s?|0)(?:\s*[1-9])(?:[\s.\-]?\d{2}){4}")

ZERO_WIDTH = "".join(["\u200b", "\u200c", "\u200d", "\ufeff"])

SEED_PATHS = (
    "/contact", "/contactez-nous", "/contact-us", "/contacts",
    "/mentions-legales", "/mentions_légales", "/mentions", "/legal", "/legals",
    "/faq", "/aide", "/support", "/help", "/sav",
    "/cgv", "/cgu", "/terms", "/privacy", "/politique-de-confidentialite",
    "/donnees-personnelles", "/donnees", "/rgpd",
)

# --------------------------- Modèles ----------------------------- #

@dataclass(frozen=True)
class Row:
    domain: str
    email: str
    source_url: str
    page_type: str
    phone: str
    contact_form_url: str
    context_snippet: str
    page_title: str


# --------------------------- Utils URL --------------------------- #

def strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host

def same_domain(u: str, root_host: str) -> bool:
    return strip_www(urlparse(u).netloc) == strip_www(root_host)

def is_blocked_host(u: str) -> bool:
    host = urlparse(u).netloc.lower()
    return any(part in host for part in BLOCKED_HOST_PARTS)

def is_asset(u: str) -> bool:
    path = urlparse(u).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTS)

def clean_url(u: str) -> str:
    """Normalise: https par défaut, pas de fragments, sans UTM/fbclid/gclid."""
    if not u:
        return u
    u = u.strip()
    parsed = urlparse(u if "://" in u else f"https://{u}")
    # drop fragment
    parsed = parsed._replace(fragment="")
    # drop tracking params
    q = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
         if not (k.lower().startswith("utm_") or k.lower() in {"gclid", "fbclid", "mc_eid"})]
    parsed = parsed._replace(query=urlencode(q))
    # normalise path empty to "/"
    path = parsed.path or "/"
    return urlunparse(parsed._replace(path=path))


# ----------------------- Session & Robots ------------------------ #

def session_with_retries(user_agent: str, retries: int, timeout: int) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": user_agent,
        "Accept-Language": "fr,fr-FR;q=0.9,en;q=0.8",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    s.request_timeout = timeout  # type: ignore[attr-defined]
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def load_robots(root: str) -> robotparser.RobotFileParser:
    rp = robotparser.RobotFileParser()
    try:
        rp.set_url(urljoin(root, "/robots.txt"))
        rp.read()
    except Exception:
        pass  # beaucoup de sites sans robots valide
    return rp

def robots_allowed(rp: robotparser.RobotFileParser, agent: str, u: str) -> bool:
    try:
        return rp.can_fetch(agent, u)
    except Exception:
        return True


# ------------------- Découverte & Classification ----------------- #

def classify_page_from_url(u: str) -> Optional[str]:
    """Retourne 'contact'|'faq'|'legal' si l'URL le suggère, sinon None."""
    p = urlparse(u).path.lower()
    # léger sur-matching volontaire pour attraper variantes
    if any(k in p for k in ("contact", "contactez", "sav", "support", "service-client", "serviceclient", "customer")):
        return "contact"
    if any(k in p for k in ("faq", "aide", "help", "questions")):
        return "faq"
    if any(k in p for k in ("mentions", "legal", "légal", "cgu", "cgv", "privacy", "confidential", "rgpd", "donnees")):
        return "legal"
    return None

def discover_target_links(base_url: str, soup: BeautifulSoup, host: str) -> Set[str]:
    """Détecte sur une page les liens internes qui matchent les mots-clés cibles."""
    out: Set[str] = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        abs_u = urljoin(base_url, href)
        abs_u, _ = urldefrag(abs_u)
        if is_asset(abs_u) or is_blocked_host(abs_u):
            continue
        if not same_domain(abs_u, host):
            continue
        if classify_page_from_url(abs_u) or any(k in urlparse(abs_u).path.lower() for k in TARGET_KEYWORDS):
            out.add(abs_u)
    return out

def seed_candidates(root: str, session: requests.Session, timeout: int) -> Set[str]:
    """Construit la liste initiale de pages cibles (chemins connus + découverte sur home)."""
    seeds: Set[str] = set()
    # chemins connus
    for p in SEED_PATHS:
        seeds.add(urljoin(root, p))
    # découverte home (si accessible)
    try:
        resp = session.get(root, timeout=timeout)
        if resp.ok and "text/html" in resp.headers.get("Content-Type", ""):
            soup = BeautifulSoup(resp.text, "html.parser")
            seeds |= discover_target_links(resp.url, soup, urlparse(root).netloc)
    except Exception:
        pass
    return {clean_url(u) for u in seeds}


# --------------------------- Extraction -------------------------- #

def deobfuscate_local(text: str) -> str:
    """Remplace at/dot obfusqués sans supprimer les espaces partout (évite collage avec mots)."""
    t = text
    replacements = [
        (r"\s*\[\s*at\s*\]\s*", "@"),
        (r"\s*\(\s*at\s*\)\s*", "@"),
        (r"\bat\b", "@"),
        (r"\s*\{\s*at\s*\}\s*", "@"),
        (r"\s*\[\s*dot\s*\]\s*", "."),
        (r"\s*\(\s*dot\s*\)\s*", "."),
        (r"\bdot\b", "."),
        (r"\s*\{\s*dot\s*\}\s*", "."),
        (r"NOSPAM", ""),
    ]
    for pat, rep in replacements:
        t = re.sub(pat, rep, t, flags=re.IGNORECASE)
    # enlever caractères invisibles
    for ch in ZERO_WIDTH:
        t = t.replace(ch, "")
    return unescape(t)

def is_valid_email(email: str) -> bool:
    e = email.strip().strip(string.punctuation)
    if not EMAIL_REGEX.fullmatch(e):
        return False
    # garde-fous simples
    if any(seg in e.lower() for seg in (".png", ".jpg", ".svg", ".css", ".js", "mailto:")):
        return False
    return True

def extract_emails_and_context(soup: BeautifulSoup) -> List[Tuple[str, str]]:
    """Retourne [(email, snippet_contexte)] depuis mailto: + texte."""
    found: List[Tuple[str, str]] = []

    # mailto:
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.lower().startswith("mailto:"):
            addr = href.split("mailto:", 1)[1].split("?", 1)[0]
            addr = deobfuscate_local(addr)
            for m in EMAIL_REGEX.findall(addr):
                if is_valid_email(m):
                    found.append((m, ""))

    # texte
    text = soup.get_text(separator=" ", strip=True)
    text = deobfuscate_local(text)
    for m in EMAIL_REGEX.finditer(text):
        email = m.group(0)
        if not is_valid_email(email):
            continue
        start = max(0, m.start() - 60)
        end = min(len(text), m.end() + 60)
        snippet = text[start:end]
        found.append((email, snippet))

    # dédoublonnage local en conservant premier snippet
    uniq: Dict[str, str] = {}
    for e, snip in found:
        uniq.setdefault(e.lower(), snip)
    return [(e, uniq[e]) for e in uniq]

def extract_phones(soup: BeautifulSoup) -> Set[str]:
    text = soup.get_text(separator=" ", strip=True)
    return set(PHONE_FR_REGEX.findall(text))

def detect_contact_form(base_url: str, soup: BeautifulSoup) -> str:
    """Retourne l'URL d'action du form si dédié (sinon page courante)."""
    form = soup.find("form")
    if not form:
        return ""
    action = (form.get("action") or "").strip()
    if not action:
        return base_url
    return urljoin(base_url, action)


# ---------------------------- Crawl -------------------------------- #

def fetch(session: requests.Session, url: str, timeout: int) -> Optional[requests.Response]:
    try:
        r = session.get(url, timeout=timeout)
        if not r.ok:
            return None
        ctype = r.headers.get("Content-Type", "")
        if "text/html" not in ctype and "application/xhtml" not in ctype:
            return None
        return r
    except requests.RequestException:
        return None

def crawl_domain(root: str, args: argparse.Namespace) -> List[Row]:
    domain = urlparse(root).netloc
    rp = load_robots(root)
    session = session_with_retries(args.user_agent, args.retries, args.timeout)
    sleep_min, sleep_max = args.sleep_min, args.sleep_max

    # Seeds
    seeds = seed_candidates(root, session, args.timeout)
    queue: Deque[Tuple[str, int, str]] = deque()
    for u in sorted(seeds):
        pt = classify_page_from_url(u) or "contact"
        queue.append((u, 0, pt))

    visited: Set[str] = set()
    results: List[Row] = []
    seen_email_key: Set[Tuple[str, str]] = set()
    pages = 0
    forms_found = 0
    emails_found = 0

    logging.info("Crawl: %s | seeds=%d", domain, len(queue))

    while queue and pages < args.max_pages_per_site:
        url, depth, page_type = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        if is_asset(url) or is_blocked_host(url) or not same_domain(url, domain):
            continue
        if not args.ignore_robots and not robots_allowed(rp, args.user_agent, url):
            continue

        logging.debug("GET %s [depth=%d,type=%s] queued=%d", url, depth, page_type, len(queue))
        time.sleep(random.uniform(sleep_min, sleep_max))

        resp = fetch(session, url, args.timeout)
        if not resp:
            continue

        pages += 1
        base = resp.url
        soup = BeautifulSoup(resp.text, "html.parser")
        title = (soup.title.string.strip() if soup.title and soup.title.string else "")

        # Extraction
        emails_ctx = extract_emails_and_context(soup)
        phones = extract_phones(soup)
        form_url = detect_contact_form(base, soup)
        if form_url:
            forms_found += 1

        # Écrit lignes (dédup par domaine+email)
        if emails_ctx:
            for email, snippet in emails_ctx:
                if args.only_same_domain:
                    # garde seulement emails du même domaine (ou sous-domaines)
                    try:
                        if strip_www(email.split("@", 1)[1].lower()) != strip_www(domain.lower()):
                            continue
                        # tolère sous-domaines
                    except Exception:
                        continue
                key = (domain, email.lower())
                if key in seen_email_key:
                    continue
                seen_email_key.add(key)
                results.append(
                    Row(
                        domain=domain,
                        email=email,
                        source_url=base,
                        page_type=page_type,
                        phone=" | ".join(sorted(phones)) if phones else "",
                        contact_form_url=form_url,
                        context_snippet=snippet[:200],
                        page_title=title,
                    )
                )
                emails_found += 1
        elif form_url:
            # utile si page contact avec uniquement formulaire
            results.append(
                Row(
                    domain=domain,
                    email="",
                    source_url=base,
                    page_type=page_type,
                    phone=" | ".join(sorted(phones)) if phones else "",
                    contact_form_url=form_url,
                    context_snippet="",
                    page_title=title,
                )
            )

        # Enfants des pages cibles
        if depth < args.depth_contact:
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                abs_u = clean_url(urljoin(base, href))
                if abs_u in visited or is_asset(abs_u) or is_blocked_host(abs_u):
                    continue
                if not same_domain(abs_u, domain):
                    continue
                next_type = classify_page_from_url(abs_u) or "contact_child"
                # on ne pousse QUE les liens considérés pertinents ou enfants des pages cibles
                if next_type in PAGE_TYPES:
                    queue.append((abs_u, depth + 1, next_type))

    logging.info("Done: %s | pages=%d emails=%d forms=%d", domain, pages, emails_found, forms_found)
    return results


# --------------------------- I/O CSV ------------------------------ #

def write_csv(rows: Iterable[Row], outfile: Path) -> None:
    outfile.parent.mkdir(parents=True, exist_ok=True)
    headers = ["domain", "email", "source_url", "page_type", "phone", "contact_form_url", "context_snippet", "page_title"]
    with outfile.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow({
                "domain": r.domain,
                "email": r.email,
                "source_url": r.source_url,
                "page_type": r.page_type,
                "phone": r.phone,
                "contact_form_url": r.contact_form_url,
                "context_snippet": r.context_snippet,
                "page_title": r.page_title,
            })


# ---------------------------- CLI -------------------------------- #

def read_urls(start_urls: List[str], file_path: Optional[Path]) -> List[str]:
    urls: List[str] = []
    if start_urls:
        urls.extend(start_urls)
    if file_path and file_path.exists():
        for ln in file_path.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            urls.append(ln)
    if not urls:
        raise SystemExit("Aucune URL fournie. Ajoutez-en à START_URLS ou créez 'urls.txt'.")
    return [clean_url(u) for u in urls]

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Scraper emails sur pages Contact/FAQ/Legal (+ enfants).")
    p.add_argument("--urls-file", type=Path, default=URLS_TXT, help="Fichier d'URLs (1 par ligne).")
    p.add_argument("--output", type=Path, default=Path("contacts.csv"), help="CSV de sortie.")
    p.add_argument("--max-pages-per-site", type=int, default=40, help="Limite de pages par domaine.")
    p.add_argument("--depth-contact", type=int, default=2, help="Profondeur de crawl depuis les pages cibles.")
    p.add_argument("--sleep-min", type=float, default=0.5, help="Pause min (politesse).")
    p.add_argument("--sleep-max", type=float, default=1.5, help="Pause max (politesse).")
    p.add_argument("--timeout", type=int, default=15, help="Timeout requêtes HTTP.")
    p.add_argument("--retries", type=int, default=2, help="Retries connexions.")
    p.add_argument("--workers", type=int, default=3, help="Domaine(s) en parallèle.")
    p.add_argument("--only-same-domain", action="store_true", help="Ne garder que les emails du même domaine.")
    p.add_argument("--ignore-robots", action="store_true", help="Ignorer robots.txt (déconseillé).")
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; ContactOnlyScraper/1.0)", help="User-Agent HTTP.")
    p.add_argument("--verbose", action="store_true", help="Logs DEBUG.")
    return p

def setup_logger(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

def main() -> None:
    args = build_arg_parser().parse_args()
    setup_logger(args.verbose)
    roots = read_urls(START_URLS, args.urls_file)
    logging.info("Total domaines: %d", len(roots))

    all_rows: List[Row] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(crawl_domain, root, args): root for root in roots}
        for fut in as_completed(futs):
            domain = urlparse(futs[fut]).netloc
            try:
                rows = fut.result()
                all_rows.extend(rows)
            except Exception as e:
                logging.warning("Erreur domaine %s: %s", domain, e)

    write_csv(all_rows, args.output)
    logging.info("Écrit %d ligne(s) dans %s", len(all_rows), args.output)

if __name__ == "__main__":
    main()

