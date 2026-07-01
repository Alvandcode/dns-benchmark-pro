import secrets

BASE = ["google.com", "cloudflare.com", "wikipedia.org"]

def random_domain():
    return f"{secrets.token_hex(3)}.{secrets.choice(BASE)}"
