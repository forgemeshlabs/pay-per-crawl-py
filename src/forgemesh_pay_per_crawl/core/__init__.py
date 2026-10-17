"""Framework-free core of ForgeMesh Pay-per-Crawl."""
from .classifier import CLASSES, Classification, Classifier, SystemResolver
from .config import DEFAULT_CLASS_POLICY, Config
from .discovery import PATHS as DISCOVERY_PATHS
from .discovery import Discovery
from .gate import Gate
from .http import Decision, Request, Response
from .keccak import keccak256, keccak256_hex
from .locks import FileNonceLock, MemoryNonceLock
from .pro import ProReporter, Stats
from .x402 import TransportError, X402, default_transport, usd_to_units

__all__ = [
    "CLASSES", "Classification", "Classifier", "SystemResolver", "Config", "DEFAULT_CLASS_POLICY", "Discovery",
    "DISCOVERY_PATHS", "Gate", "Decision", "Request", "Response", "keccak256", "keccak256_hex", "FileNonceLock",
    "MemoryNonceLock", "ProReporter", "Stats", "TransportError", "X402", "default_transport", "usd_to_units",
    "classify", "build_challenge", "extract_payment", "precheck", "verify_and_settle",
]


# Function-style entry points over the classes, for people who want the pieces.
def classify(ua, headers=None, ip="", classifier=None):
    return (classifier or Classifier()).classify(ua, headers, ip)


def build_challenge(x402: X402, resource_url, description=""):
    """(PAYMENT-REQUIRED value, v1 body dict, WWW-Authenticate value) for one resource."""
    from .x402 import b64_encode_json
    return (b64_encode_json(x402.envelope_v2(resource_url, description)),
            x402.body_v1(resource_url, description), x402.mpp_challenge(description))


def extract_payment(x402, headers, resource_url):
    return x402.extract_payment(headers, resource_url)


def precheck(x402, payment, resource_url=""):
    return x402.precheck(payment, resource_url)


def verify_and_settle(x402, payment, resource_url):
    return x402.verify_and_settle(payment, resource_url)
