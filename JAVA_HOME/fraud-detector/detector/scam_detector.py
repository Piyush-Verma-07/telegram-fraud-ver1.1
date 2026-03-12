import re
import tldextract
import os


# Words commonly used in scam domains
suspicious_domain_words = [
    "login",
    "verify",
    "secure",
    "bonus",
    "reward",
    "gift",
    "bank",
    "wallet",
    "upi",
    "pay"
]


# List of common shortened URL services
short_url_services = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly",
    "is.gd"
]


# List of suspicious keywords
suspicious_keywords = [
    "lottery",
    "reward",
    "claim",
    "urgent",
    "verify",
    "otp",
    "win"
]


# Load scam patterns from dataset file
def load_scam_patterns():

    patterns = []

    # Get project root directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Build correct path to dataset
    file_path = os.path.join(base_dir, "data", "scam_patterns.txt")

    try:
        with open(file_path, "r") as file:

            for line in file:
                patterns.append(line.strip().lower())

    except:
        print("Scam pattern dataset not found")

    return patterns


# Load patterns once
scam_patterns = load_scam_patterns()


# Function to calculate similarity between two sentences
def jaccard_similarity(text1, text2):

    # Remove punctuation
    text1 = re.sub(r'[^\w\s]', '', text1)
    text2 = re.sub(r'[^\w\s]', '', text2)

    words1 = set(text1.split())
    words2 = set(text2.split())

    intersection = words1.intersection(words2)
    union = words1.union(words2)

    if len(union) == 0:
        return 0

    similarity = len(intersection) / len(union)

    return similarity


# Main function to analyze suspicious messages
def analyze_message(message):

    score = 0
    reasons = []

    # Convert message to lowercase
    text = message.lower()

    # --------------------------------
    # Keyword Detection
    # --------------------------------
    for word in suspicious_keywords:

        if word in text:
            score += 20
            reasons.append("Suspicious keyword detected: " + word)

    # --------------------------------
    # Pattern Detection
    # --------------------------------
    pattern_matched = False

    for pattern in scam_patterns:

        if pattern in text:
            score += 40
            reasons.append("Matched known scam pattern: " + pattern)
            pattern_matched = True
            break

    # --------------------------------
    # Similarity Detection
    # --------------------------------
    if not pattern_matched:

        for pattern in scam_patterns:

            similarity = jaccard_similarity(text, pattern)

            if similarity > 0.3:
                score += 30
                reasons.append("Message similar to scam pattern: " + pattern)
                break

    # --------------------------------
    # URL Detection
    # --------------------------------
    urls = re.findall(r'https?://\S+', text)

    if urls:
        score += 20
        reasons.append("Message contains external link")

    # --------------------------------
    # URL Analysis
    # --------------------------------
    for url in urls:

        # Extract domain
        domain_info = tldextract.extract(url)

        domain = domain_info.domain
        suffix = domain_info.suffix

        full_domain = domain + "." + suffix

        reasons.append("Detected domain: " + full_domain)

        # Detect shortened links
        for short in short_url_services:

            if short in url:
                score += 30
                reasons.append("Shortened URL detected: " + url)

        # Detect suspicious domain words
        for word in suspicious_domain_words:

            if word in url:
                score += 25
                reasons.append("Suspicious word in URL: " + word)

    # Limit score to 100
    if score > 100:
        score = 100

    return score, reasons