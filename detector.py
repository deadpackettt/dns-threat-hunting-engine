from scapy.all import (
    rdpcap,
    sniff,
    DNS,
    DNSQR
)

from collections import (
    Counter,
    defaultdict
)

from math import log2
from termcolor import colored
from datetime import datetime

import argparse
import json
import csv
import re
import statistics


# =========================================================
# LOAD CONFIG
# =========================================================

with open("config.json", "r") as f:
    CONFIG = json.load(f)

ENTROPY_THRESHOLD = CONFIG[
    "entropy_threshold"
]

LONG_SUBDOMAIN_LENGTH = CONFIG[
    "long_subdomain_length"
]

HIGH_FREQUENCY_THRESHOLD = CONFIG[
    "high_frequency_threshold"
]

BEACONING_MIN_INTERVAL = CONFIG[
    "beaconing_min_interval"
]

BEACONING_STDEV_THRESHOLD = CONFIG[
    "beaconing_stdev_threshold"
]

DGA_CONSONANT_THRESHOLD = CONFIG[
    "dga_consonant_threshold"
]

SUBDOMAIN_VARIATION_THRESHOLD = CONFIG[
    "subdomain_variation_threshold"
]

LARGE_QUERY_LENGTH = CONFIG[
    "large_query_length"
]

MODE = CONFIG["mode"]

SUSPICIOUS_TLDS = CONFIG[
    "suspicious_tlds"
]

WHITELIST = CONFIG[
    "whitelist"
]


# =========================================================
# LOCAL NETWORK FILTERS
# =========================================================

LOCAL_PATTERNS = [
    "_tcp.local",
    "_udp.local",
    "_googlecast",
    ".local",
    "in-addr.arpa"
]


# =========================================================
# TIMESTAMP
# =========================================================

TIMESTAMP = datetime.now().strftime(
    "%Y%m%d_%H%M%S"
)

REPORT_JSON = (
    f"reports/report_{TIMESTAMP}.json"
)

REPORT_CSV = (
    f"reports/alerts_{TIMESTAMP}.csv"
)

IOC_FILE = (
    f"reports/iocs_{TIMESTAMP}.txt"
)


# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(data):

    if not data:
        return 0

    frequency = {}

    for char in data:

        frequency[char] = (
            frequency.get(char, 0) + 1
        )

    entropy = 0
    length = len(data)

    for count in frequency.values():

        probability = count / length

        entropy -= (
            probability * log2(probability)
        )

    return entropy


# =========================================================
# CONSONANT RATIO (DGA HEURISTIC)
# =========================================================

def consonant_ratio(text):

    vowels = "aeiou"

    consonants = 0
    letters = 0

    for c in text.lower():

        if c.isalpha():

            letters += 1

            if c not in vowels:
                consonants += 1

    if letters == 0:
        return 0

    return consonants / letters


# =========================================================
# WHITELIST
# =========================================================

def is_whitelisted(domain):

    for item in WHITELIST:

        if item in domain:
            return True

    return False


# =========================================================
# LOCAL TRAFFIC FILTER
# =========================================================

def is_local_noise(domain):

    for pattern in LOCAL_PATTERNS:

        if pattern in domain:
            return True

    return False


# =========================================================
# BEACONING DETECTION
# =========================================================

def detect_beaconing(timestamps):

    if len(timestamps) < 4:
        return False, []

    intervals = []

    for i in range(1, len(timestamps)):

        delta = round(
            timestamps[i] - timestamps[i - 1],
            2
        )

        intervals.append(delta)

    if len(intervals) < 3:
        return False, intervals

    try:

        average_interval = statistics.mean(
            intervals
        )

        stdev = statistics.stdev(intervals)

        if (
            average_interval >
            BEACONING_MIN_INTERVAL
            and
            stdev <
            BEACONING_STDEV_THRESHOLD
        ):

            return True, intervals

    except:
        pass

    return False, intervals


# =========================================================
# BURST DETECTION
# =========================================================

def detect_burst(timestamps):

    if len(timestamps) < 5:
        return False

    time_window = (
        max(timestamps) - min(timestamps)
    )

    if time_window <= 2:
        return True

    return False


# =========================================================
# NXDOMAIN DETECTION
# =========================================================

def is_nxdomain(packet):

    try:

        if (
            packet.haslayer(DNS)
            and
            packet[DNS].qr == 1
            and
            packet[DNS].rcode == 3
        ):

            return True

    except:
        pass

    return False


# =========================================================
# DETECTION MODE
# =========================================================

def get_threshold():

    threshold = 3

    if MODE == "strict":
        threshold = 5

    elif MODE == "malware":
        threshold = 2

    return threshold


# =========================================================
# PROCESS PACKETS
# =========================================================

def process_packets(packets):

    domains = []
    txt_queries = []

    domain_timestamps = defaultdict(list)

    nxdomain_counter = Counter()

    unique_subdomains = defaultdict(set)

    # -----------------------------------------------------
    # Extract DNS
    # -----------------------------------------------------

    for packet in packets:

        if packet.haslayer(DNSQR):

            try:

                query = (
                    packet[DNSQR]
                    .qname
                    .decode(errors="ignore")
                    .rstrip(".")
                )

                domains.append(query)

                domain_timestamps[
                    query
                ].append(float(packet.time))

                parts = query.split(".")

                if len(parts) >= 2:

                    parent = ".".join(parts[-2:])

                    subdomain = parts[0]

                    unique_subdomains[
                        parent
                    ].add(subdomain)

                # TXT queries
                if packet.haslayer(DNS):

                    query_type = (
                        packet[DNS]
                        .qd
                        .qtype
                    )

                    if query_type == 16:
                        txt_queries.append(query)

                # NXDOMAIN
                if is_nxdomain(packet):

                    nxdomain_counter[
                        query
                    ] += 1

            except:
                pass

    counter = Counter(domains)

    parent_domains = defaultdict(int)

    for domain in domains:

        parts = domain.split(".")

        if len(parts) >= 2:

            parent = ".".join(parts[-2:])

            parent_domains[parent] += 1

    print(colored(
        "\n=== DNS Threat Hunting Detection ===\n",
        "cyan"
    ))

    alerts = []
    ioc_domains = []

    medium_alerts = 0
    high_alerts = 0

    threshold = get_threshold()

    # -----------------------------------------------------
    # Detection Logic
    # -----------------------------------------------------

    for domain, count in counter.items():

        if is_whitelisted(domain):
            continue

        if is_local_noise(domain):
            continue

        score = 0
        reasons = []
        categories = []

        parts = domain.split(".")

        if len(parts) < 2:
            continue

        subdomain = parts[0]
        tld = parts[-1]

        parent = ".".join(parts[-2:])

        entropy = calculate_entropy(
            subdomain
        )

        ratio = consonant_ratio(
            subdomain
        )

        # -------------------------------------------------
        # Long subdomain
        # -------------------------------------------------

        if (
            len(subdomain)
            >
            LONG_SUBDOMAIN_LENGTH
        ):

            score += 1

            reasons.append(
                "Long subdomain"
            )

            categories.append(
                "DNS Tunneling"
            )

        # -------------------------------------------------
        # High entropy
        # -------------------------------------------------

        if entropy > ENTROPY_THRESHOLD:

            score += 1

            reasons.append(
                f"High entropy ({entropy:.2f})"
            )

        # -------------------------------------------------
        # High frequency
        # -------------------------------------------------

        if (
            count >
            HIGH_FREQUENCY_THRESHOLD
        ):

            score += 1

            reasons.append(
                f"High frequency ({count} requests)"
            )

        # -------------------------------------------------
        # Suspicious TLD
        # -------------------------------------------------

        if (
            tld.lower()
            in
            SUSPICIOUS_TLDS
        ):

            score += 2

            reasons.append(
                f"Suspicious TLD (.{tld})"
            )

        # -------------------------------------------------
        # Hex/random subdomain
        # -------------------------------------------------

        if re.fullmatch(
            r"[a-f0-9]{8,}",
            subdomain.lower()
        ):

            score += 2

            reasons.append(
                "Hex/random subdomain"
            )

            categories.append("DGA")

        # -------------------------------------------------
        # Base64-like subdomain
        # -------------------------------------------------

        if re.fullmatch(
            r"[A-Za-z0-9+/=]{12,}",
            subdomain
        ):

            score += 2

            reasons.append(
                "Base64-like subdomain"
            )

            categories.append(
                "Encoded Payload"
            )

        # -------------------------------------------------
        # Large query
        # -------------------------------------------------

        if len(domain) > LARGE_QUERY_LENGTH:

            score += 2

            reasons.append(
                f"Large DNS query ({len(domain)} chars)"
            )

            categories.append(
                "DNS Exfiltration"
            )

        # -------------------------------------------------
        # DGA heuristic
        # -------------------------------------------------

        if (
            ratio >
            DGA_CONSONANT_THRESHOLD
        ):

            score += 2

            reasons.append(
                f"DGA-like consonant ratio ({ratio:.2f})"
            )

            categories.append("DGA")

        # -------------------------------------------------
        # TXT query
        # -------------------------------------------------

        if domain in txt_queries:

            score += 3

            reasons.append(
                "TXT query detected"
            )

            categories.append(
                "DNS Tunneling"
            )

        # -------------------------------------------------
        # Parent frequency
        # -------------------------------------------------

        if parent_domains[parent] > 10:

            score += 1

            reasons.append(
                f"Frequent parent domain "
                f"({parent_domains[parent]} queries)"
            )

        # -------------------------------------------------
        # Subdomain variation
        # -------------------------------------------------

        if (
            len(unique_subdomains[parent])
            >
            SUBDOMAIN_VARIATION_THRESHOLD
        ):

            score += 3

            reasons.append(
                f"High subdomain variation "
                f"({len(unique_subdomains[parent])})"
            )

            categories.append(
                "DNS Tunneling"
            )

        # -------------------------------------------------
        # Beaconing
        # -------------------------------------------------

        beaconing, intervals = (
            detect_beaconing(
                domain_timestamps[domain]
            )
        )

        if beaconing:

            score += 4

            reasons.append(
                f"Beaconing detected "
                f"({intervals})"
            )

            categories.append(
                "Beaconing"
            )

        # -------------------------------------------------
        # Burst activity
        # -------------------------------------------------

        if detect_burst(
            domain_timestamps[domain]
        ):

            score += 2

            reasons.append(
                "DNS burst activity"
            )

        # -------------------------------------------------
        # NXDOMAIN
        # -------------------------------------------------

        if nxdomain_counter[domain] > 0:

            score += 2

            reasons.append(
                f"NXDOMAIN responses "
                f"({nxdomain_counter[domain]})"
            )

            categories.append("DGA")

        # -------------------------------------------------
        # Confidence Score
        # -------------------------------------------------

        confidence = min(score * 12, 100)

        # -------------------------------------------------
        # Final Threshold
        # -------------------------------------------------

        if score >= threshold:

            severity = "MEDIUM"
            color = "yellow"

            if score >= 8:

                severity = "HIGH"
                color = "red"

                high_alerts += 1

            else:
                medium_alerts += 1

            alert = {

                "severity": severity,
                "domain": domain,
                "parent": parent,
                "requests": count,
                "entropy": round(
                    entropy,
                    2
                ),
                "risk_score": score,
                "confidence": confidence,
                "categories": list(
                    set(categories)
                ),
                "reasons": reasons
            }

            alerts.append(alert)

            ioc_domains.append(domain)

            print(colored(
                f"[{severity}] "
                f"Suspicious Domain Detected",
                color
            ))

            print(
                f"Domain       : {domain}"
            )

            print(
                f"Parent       : {parent}"
            )

            print(
                f"Category     : "
                f"{', '.join(set(categories))}"
            )

            print(
                f"Confidence   : "
                f"{confidence}%"
            )

            print(
                f"Requests     : {count}"
            )

            print(
                f"Entropy      : {entropy:.2f}"
            )

            print(
                f"Risk Score   : {score}"
            )

            print(
                f"Reasons      : "
                f"{', '.join(reasons)}"
            )

            print("-" * 70)

    # =====================================================
    # STATISTICS
    # =====================================================

    print(colored(
        "\n=== Statistics ===",
        "cyan"
    ))

    print(
        f"Total DNS Queries     : "
        f"{len(domains)}"
    )

    print(
        f"Unique Domains        : "
        f"{len(counter)}"
    )

    print(
        f"TXT Queries           : "
        f"{len(txt_queries)}"
    )

    print(
        f"Suspicious Alerts     : "
        f"{len(alerts)}"
    )

    print(
        f"Medium Alerts         : "
        f"{medium_alerts}"
    )

    print(
        f"High Alerts           : "
        f"{high_alerts}"
    )

    # =====================================================
    # TOP PARENT DOMAINS
    # =====================================================

    print(colored(
        "\n=== Top Parent Domains ===",
        "cyan"
    ))

    for parent, freq in sorted(
        parent_domains.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]:

        print(f"{parent:<35} {freq}")

    # =====================================================
    # SAVE JSON
    # =====================================================

    with open(REPORT_JSON, "w") as f:

        json.dump(
            alerts,
            f,
            indent=4
        )

    # =====================================================
    # SAVE IOCS
    # =====================================================

    with open(IOC_FILE, "w") as f:

        for domain in ioc_domains:
            f.write(domain + "\n")

    # =====================================================
    # SAVE CSV
    # =====================================================

    with open(
        REPORT_CSV,
        "w",
        newline=""
    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "Severity",
            "Domain",
            "Parent",
            "Category",
            "Confidence",
            "Requests",
            "Entropy",
            "Risk Score",
            "Reasons"
        ])

        for alert in alerts:

            writer.writerow([
                alert["severity"],
                alert["domain"],
                alert["parent"],
                ", ".join(alert["categories"]),
                alert["confidence"],
                alert["requests"],
                alert["entropy"],
                alert["risk_score"],
                "; ".join(alert["reasons"])
            ])

    print(colored(
        f"\n[+] JSON report saved "
        f"to {REPORT_JSON}",
        "green"
    ))

    print(colored(
        f"[+] IOC list saved "
        f"to {IOC_FILE}",
        "green"
    ))

    print(colored(
        f"[+] CSV report saved "
        f"to {REPORT_CSV}",
        "green"
    ))

    print(colored(
        "[+] Detection completed.\n",
        "green"
    ))


# =========================================================
# LIVE MODE
# =========================================================

def live_capture(interface):

    print(colored(
        f"\n[+] Starting live capture "
        f"on {interface}...\n",
        "green"
    ))

    captured_packets = sniff(
        iface=interface,
        timeout=30
    )

    process_packets(captured_packets)


# =========================================================
# CLI
# =========================================================

parser = argparse.ArgumentParser(
    description="Advanced DNS Threat Hunting Engine v8"
)

group = parser.add_mutually_exclusive_group(
    required=True
)

group.add_argument(
    "-p",
    "--pcap",
    help="Path to PCAP file"
)

group.add_argument(
    "-l",
    "--live",
    help="Live capture interface"
)

args = parser.parse_args()


# =========================================================
# MAIN
# =========================================================

if args.pcap:

    print(colored(
        "\n[+] Loading PCAP...\n",
        "green"
    ))

    packets = rdpcap(args.pcap)

    process_packets(packets)

elif args.live:

    live_capture(args.live)
