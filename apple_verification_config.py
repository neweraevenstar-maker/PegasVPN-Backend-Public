import os

def verification_target():
    billing = os.getenv("PEGASVPN_BILLING_ENV", "production").lower()
    deployment = os.getenv("PEGASVPN_DEPLOYMENT", "production").lower()

    if billing == "sandbox" and deployment == "staging":
        return "sandbox", None

    if billing == "production" and deployment == "production":
        app_id = os.getenv("PEGASVPN_APP_APPLE_ID", "")
        if not app_id.isdecimal() or int(app_id) == 0:
            raise RuntimeError("Apple app ID not configured")
        return "production", int(app_id)

    raise RuntimeError("Invalid billing environment")
