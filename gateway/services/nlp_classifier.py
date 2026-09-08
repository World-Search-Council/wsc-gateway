"""
WSC NLP Classification & Centroid Analysis Service
Maps websites and content into Google Cloud Natural Language Taxonomy (v2).
"""

import os
import re
import math
from collections import Counter
from typing import Dict, List, Tuple, Optional, Any
import logging

logger = logging.getLogger("wsc-nlp-classifier")

# Google Cloud Natural Language API standard category taxonomy labels
GOOGLE_NLP_TAXONOMY: Dict[str, Dict[str, any]] = {
    "/Shopping/Apparel": {
        "label": "E-Commerce: Fashion & Apparel",
        "keywords": [
            "fashion", "clothing", "apparel", "shoes", "sneakers", "dress", "shirts", "pants",
            "hoodie", "jewelry", "accessories", "outfit", "wear", "kleidung", "mode", "schuhe",
            "damenmode", "herrenmode", "textilien", "boutique", "designer", "style"
        ]
    },
    "/Shopping/Consumer Electronics": {
        "label": "E-Commerce: Consumer Electronics",
        "keywords": [
            "electronics", "gadgets", "audio", "headphones", "smartphone", "laptop", "hardware",
            "camera", "smartwatch", "elektronik", "fernseher", "audio", "hifi", "pc", "gaming",
            "zubehör", "kabel", "computer", "tablets", "technik"
        ]
    },
    "/Shopping/Home & Garden": {
        "label": "E-Commerce: Home & Living",
        "keywords": [
            "furniture", "home", "garden", "decor", "interior", "kitchen", "living", "sofa",
            "table", "bed", "lighting", "möbel", "wohnen", "garten", "dekoration", "küche",
            "einrichtung", "lampen", "schlafzimmer", "heimwerker"
        ]
    },
    "/Computers & Electronics/Enterprise Software": {
        "label": "B2B SaaS & Enterprise Software",
        "keywords": [
            "saas", "software", "api", "cloud", "platform", "enterprise", "crm", "erp",
            "workflow", "automation", "integration", "dashboard", "analytics", "developer",
            "security", "b2b", "solution", "infrastructure", "devops", "schnittstelle"
        ]
    },
    "/Finance/Banking & Insurance": {
        "label": "Finance, Banking & Insurance",
        "keywords": [
            "finance", "banking", "insurance", "loan", "mortgage", "credit", "investment",
            "wealth", "fintech", "finanzen", "kredit", "versicherung", "krypto", "anlage",
            "bank", "zinsen", "aktien", "steuern", "portfolio", "vorsorge"
        ]
    },
    "/Health/Medical & Wellness": {
        "label": "Health, Medical & Wellness",
        "keywords": [
            "health", "medical", "supplements", "vitamins", "fitness", "wellness", "doctor",
            "clinic", "therapy", "gesundheit", "medizin", "nahrungsergänzung", "apotheke",
            "sport", "ernährung", "physiotherapie", "pflege", "zahnarzt", "vitamine"
        ]
    },
    "/Food & Drink/Restaurants & Groceries": {
        "label": "Food, Groceries & Gastronomy",
        "keywords": [
            "food", "drink", "restaurant", "groceries", "recipe", "delivery", "coffee", "wine",
            "beer", "bakery", "lebensmittel", "essen", "trinken", "rezept", "supermarkt",
            "lieferservice", "kaffee", "wein", "bio", "gastronomie", "speisekarte"
        ]
    },
    "/Business & Industrial/Services": {
        "label": "B2B Professional Services & Agencies",
        "keywords": [
            "agency", "consulting", "logistics", "industrial", "marketing", "recruiting",
            "legal", "audit", "agentur", "beratung", "dienstleistung", "handwerk", "kanzlei",
            "logistik", "werbeagentur", "maschinenbau", "industrie", "steuerberater"
        ]
    },
    "/News & Media/Technology": {
        "label": "Tech Media, News & Content Portals",
        "keywords": [
            "news", "tech", "magazine", "review", "article", "journal", "guide", "tutorial",
            "insights", "nachrichten", "magazin", "testbericht", "artikel", "portal",
            "blog", "ratgeber", "trends", "vergleich"
        ]
    },
    "/Travel & Tourism": {
        "label": "Travel, Tourism & Hospitality",
        "keywords": [
            "travel", "hotel", "flights", "booking", "tourism", "vacation", "resort", "destination",
            "reisen", "urlaub", "unterkunft", "ferienwohnung", "flüge", "kreuzfahrt", "tourismus",
            "städtereise", "wellnesshotel"
        ]
    }
}


def _tokenize(text: str) -> List[str]:
    """Clean and tokenize text into lowercase words."""
    if not text:
        return []
    words = re.findall(r"\b[a-zA-ZäöüÄÖÜß]{3,}\b", text.lower())
    return words


def _build_centroid_vectors() -> Dict[str, Dict[str, float]]:
    """Build normalized term-frequency vectors for all Google NLP taxonomy categories."""
    centroids = {}
    for cat_key, meta in GOOGLE_NLP_TAXONOMY.items():
        kw_counts = Counter(meta["keywords"])
        length = math.sqrt(sum(cnt * cnt for cnt in kw_counts.values()))
        centroids[cat_key] = {k: v / length for k, v in kw_counts.items()} if length > 0 else {}
    return centroids


_CENTROID_VECTORS = _build_centroid_vectors()


def classify_text_centroid(text: str) -> Tuple[str, str, float]:
    """
    Classifies input text against Google NLP taxonomy centroids using Cosine Similarity.
    Returns: (vertical_path, vertical_label, confidence_score)
    """
    tokens = _tokenize(text)
    if not tokens:
        return "/Shopping/Apparel", GOOGLE_NLP_TAXONOMY["/Shopping/Apparel"]["label"], 0.50

    doc_counts = Counter(tokens)
    doc_len = math.sqrt(sum(cnt * cnt for cnt in doc_counts.values()))
    if doc_len == 0:
        return "/Shopping/Apparel", GOOGLE_NLP_TAXONOMY["/Shopping/Apparel"]["label"], 0.50

    doc_vec = {k: v / doc_len for k, v in doc_counts.items()}

    best_cat = "/Shopping/Apparel"
    best_score = 0.0

    for cat_key, cat_vec in _CENTROID_VECTORS.items():
        dot_product = sum(doc_vec.get(term, 0.0) * weight for term, weight in cat_vec.items())
        if dot_product > best_score:
            best_score = dot_product
            best_cat = cat_key

    # Normalize confidence into 0.50 .. 0.98 range
    confidence = min(0.98, max(0.50, round(0.50 + best_score * 1.5, 2)))
    label = GOOGLE_NLP_TAXONOMY[best_cat]["label"]

    return best_cat, label, confidence


async def classify_via_google_nlp_api(text: str, api_key: Optional[str] = None) -> Optional[Tuple[str, str, float]]:
    """
    Optional: Calls Google Cloud Natural Language API classifyText endpoint (if API Key is configured).
    Uses free quota (up to 5,000 units/month).
    """
    key = api_key or os.getenv("GOOGLE_NLP_API_KEY", "")
    if not key or len(text.strip().split()) < 20:
        return None

    url = f"https://language.googleapis.com/v1/documents:classifyText?key={key}"
    payload = {
        "document": {
            "type": "PLAIN_TEXT",
            "content": text[:4000]
        }
    }

    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                cats = data.get("categories", [])
                if cats:
                    top_cat = cats[0]
                    cat_name = top_cat.get("name", "")
                    conf = float(top_cat.get("confidence", 0.75))
                    
                    # Match to our top-level Google NLP taxonomy
                    for known_cat, meta in GOOGLE_NLP_TAXONOMY.items():
                        if cat_name.startswith(known_cat) or known_cat in cat_name:
                            return known_cat, meta["label"], round(conf, 2)

                    return cat_name, cat_name.split("/")[-1], round(conf, 2)
    except Exception as e:
        logger.warning(f"Google Cloud NLP API call failed: {e}")

    return None
