from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from urllib.parse import urlparse
from urllib.parse import urljoin
import ipaddress
import re
import socket
import ssl
import certifi
import httpx
import os
import json
import pymysql
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
def save_scan_history(
    scanned_url,
    trust_score,
    risk_score,
    risk_level,
    risk_factors,
    recommendations,
):
    connection = None
    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "3307")),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "digital_trust_score"),
            connect_timeout=5,
        )

        with connection.cursor() as cursor:
            sql = """
                INSERT INTO scan_history (
                    scanned_url,
                    trust_score,
                    risk_score,
                    risk_level,
                    risk_factors,
                    recommendations
                )
                VALUES (%s, %s, %s, %s, %s, %s)
            """

            cursor.execute(
                sql,
                (
                    scanned_url,
                    trust_score,
                    risk_score,
                    risk_level,
                    json.dumps(risk_factors),
                    json.dumps(recommendations),
                ),
            )

        connection.commit()
        return True

    except Exception as error:
        print("Could not save scan history:", error)
        return False

    finally:
        if connection is not None:
            connection.close()

app = FastAPI(
    title="AI-Based Digital Trust Score Platform",
    description="API for analyzing digital security risks.",
    version="1.0.0",
)

# Allow the local React frontend to connect to FastAPI.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ "http://localhost:5173",
                    "http://127.0.0.1:5173",
                    "https://digital-trust-score-platform-hb008m8mn-digital-trust-score-team.vercel.app",
],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def is_public_ip(ip_address: str) -> bool:
    """Return True only for globally routable IP addresses."""
    try:
        return ipaddress.ip_address(ip_address).is_global
    except ValueError:
        return False


def validate_public_url(url: str) -> tuple[bool, str]:
    """Validate an HTTP(S) URL and reject non-public destinations."""
    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return False, "The URL has no valid hostname."

        if parsed.username or parsed.password:
            return False, "URLs containing embedded credentials are not allowed."

        if parsed.port is not None and parsed.port not in (80, 443):
            return False, "Only ports 80 and 443 are allowed."

        hostname = parsed.hostname

        try:
            ip = ipaddress.ip_address(hostname)
            addresses = [str(ip)]
        except ValueError:
            try:
                results = socket.getaddrinfo(
                    hostname,
                    parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
                addresses = sorted({result[4][0] for result in results})
            except socket.gaierror:
                return False, "The hostname could not be resolved."

        if not addresses:
            return False, "No IP addresses were found for this hostname."

        if not all(is_public_ip(address) for address in addresses):
            return False, "The URL resolves to a non-public IP address."

        return True, "URL passed public-address validation."

    except ValueError:
        return False, "The URL contains an invalid port or address."


def analyze_redirects(start_url: str, max_redirects: int = 5) -> dict:
    """
    Inspect a redirect chain manually, validating each URL before requesting it.
    Educational prototype only; DNS rebinding protection requires a network layer
    that pins connections to the validated IP addresses.
    """
    current_url = start_url
    redirect_chain = []
    visited_urls = set()

    try:
        # Redirects are handled one hop at a time. TLS verification remains enabled.
        with httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(5.0),
            trust_env=False,
            verify=certifi.where(),
        ) as client:
            for hop in range(max_redirects + 1):
                valid, reason = validate_public_url(current_url)
                if not valid:
                    return {
                        "success": False,
                        "redirect_chain": redirect_chain,
                        "final_url": current_url,
                        "message": f"Destination blocked: {reason}",
                    }

                normalized_url = str(httpx.URL(current_url))
                if normalized_url in visited_urls:
                    return {
                        "success": False,
                        "redirect_chain": redirect_chain,
                        "final_url": current_url,
                        "message": "Redirect loop detected.",
                    }
                visited_urls.add(normalized_url)

                response = client.get(
                    current_url,
                    headers={"Range": "bytes=0-0"},
                )

                location = response.headers.get("location")
                if response.status_code not in (301, 302, 303, 307, 308) or not location:
                    return {
                        "success": True,
                        "redirect_chain": redirect_chain,
                        "redirect_count": len(redirect_chain),
                        "final_url": current_url,
                        "http_status": response.status_code,
                        "message": "Redirect analysis completed.",
                    }

                next_url = urljoin(current_url, location)
                redirect_chain.append({
                    "from": current_url,
                    "status_code": response.status_code,
                    "to": next_url,
                })
                current_url = next_url

                if hop == max_redirects:
                    return {
                        "success": False,
                        "redirect_chain": redirect_chain,
                        "redirect_count": len(redirect_chain),
                        "final_url": current_url,
                        "message": "Maximum redirect limit reached.",
                    }

    except httpx.HTTPError as exc:
        return {
            "success": False,
            "redirect_chain": redirect_chain,
            "redirect_count": len(redirect_chain),
            "final_url": current_url,
            "message": f"Could not complete redirect analysis: {type(exc).__name__}",
        }

    return {
        "success": False,
        "redirect_chain": redirect_chain,
        "redirect_count": len(redirect_chain),
        "final_url": current_url,
        "message": "Redirect analysis stopped.",
    }


@app.get("/")
def home():
    return {
        "message": "Digital Trust Score Platform API is running!",
        "status": "success",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "digital-trust-score-backend",
    }


class URLScanRequest(BaseModel):
    url: HttpUrl


@app.post("/scan/url")
def scan_url(request: URLScanRequest):
    url = str(request.url)
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    scheme = parsed_url.scheme.lower()

    # Do not request a URL unless it passes the initial destination check.
    valid, validation_message = validate_public_url(url)
    if not valid:
        raise HTTPException(status_code=400, detail=validation_message)

    risk_factors = []
    checks = []

    # Check DNS resolution.
    try:
        ip_addresses = sorted({
            result[4][0]
            for result in socket.getaddrinfo(
                hostname,
                parsed_url.port or (443 if scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        })

        checks.append({
            "name": "DNS resolution",
            "status": "pass",
            "details": f"Domain resolved to {len(ip_addresses)} IP address(es).",
        })

    except socket.gaierror:
        ip_addresses = []
        risk_factors.append("The domain could not be resolved through DNS.")
        checks.append({
            "name": "DNS resolution",
            "status": "warning",
            "details": "The domain could not be resolved. Check the domain or try again later.",
        })

    # Check SSL/TLS certificate.
    if scheme == "https":
        try:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            port = parsed_url.port or 443

            with socket.create_connection((hostname, port), timeout=5) as connection:
                with ssl_context.wrap_socket(
                    connection,
                    server_hostname=hostname,
                ) as secure_socket:
                    secure_socket.getpeercert()

            checks.append({
                "name": "SSL/TLS certificate",
                "status": "pass",
                "details": "The certificate passed Python's default certificate and hostname verification.",
            })

        except (ssl.SSLError, socket.timeout, socket.gaierror, OSError) as error:
            risk_factors.append(
                "The SSL/TLS certificate or secure connection could not be verified."
            )
            checks.append({
                "name": "SSL/TLS certificate",
                "status": "warning",
                "details": f"Certificate verification failed: {type(error).__name__}",
            })
    else:
        checks.append({
            "name": "SSL/TLS certificate",
            "status": "warning",
            "details": "This URL uses HTTP, so an HTTPS certificate check was not performed.",
        })

    # Check HTTPS.
    if scheme == "https":
        checks.append({
            "name": "HTTPS connection",
            "status": "pass",
            "details": "The URL uses HTTPS.",
        })
    else:
        risk_factors.append("The URL does not use HTTPS.")
        checks.append({
            "name": "HTTPS connection",
            "status": "warning",
            "details": "The URL does not use HTTPS.",
        })

    # Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
        risk_factors.append("The URL uses an IP address instead of a domain name.")
        checks.append({
            "name": "Hostname check",
            "status": "warning",
            "details": "The hostname is an IP address.",
        })
    except ValueError:
        checks.append({
            "name": "Hostname check",
            "status": "pass",
            "details": "The hostname is not a plain IP address.",
        })

    # Check for suspicious URL patterns.
    suspicious_patterns = {
        "URL contains an @ symbol": r"@",
        "URL contains a URL-shortening style hostname":
            r"^(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly)$",
        "URL contains an unusually long hostname": r".{50,}",
    }

    for description, pattern in suspicious_patterns.items():
        value_to_check = hostname if "hostname" in description else url
        if re.search(pattern, value_to_check, re.IGNORECASE):
            risk_factors.append(description)
            checks.append({
                "name": "Suspicious URL pattern",
                "status": "warning",
                "details": description,
            })

    # Analyze redirects. This may fail for sites that block automated requests.
    redirect_analysis = analyze_redirects(url)
    if redirect_analysis["redirect_count"] > 0:
        checks.append({
            "name": "URL redirect analysis",
            "status": "warning" if not redirect_analysis["success"] else "pass",
            "details": (
                f"Found {redirect_analysis['redirect_count']} redirect(s). "
                f"{redirect_analysis['message']}"
            ),
        })
    else:
        checks.append({
            "name": "URL redirect analysis",
            "status": "pass" if redirect_analysis["success"] else "warning",
            "details": redirect_analysis["message"],
        })

    if not redirect_analysis["success"]:
        risk_factors.append("URL redirect analysis could not be fully completed.")


    # Calculate a basic heuristic score, not an AI verdict.
    risk_score = min(len(risk_factors) * 20, 100)
    trust_score = 100 - risk_score

    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Recommendations.
    recommendations = []

    if scheme != "https":
        recommendations.append(
            "Avoid entering passwords or personal information on this URL unless you can verify it independently."
        )

    if any("IP address" in factor for factor in risk_factors):
        recommendations.append(
            "Verify the website's identity through an official, trusted source before interacting with it."
        )

    if any("@ symbol" in factor for factor in risk_factors):
        recommendations.append(
            "Inspect the URL carefully: an @ symbol can make a URL misleading. Verify the destination before proceeding."
        )

    if any("shortening" in factor for factor in risk_factors):
        recommendations.append(
            "URL shorteners hide the final destination. Verify the destination before opening the link."
        )

    if any("long hostname" in factor for factor in risk_factors):
        recommendations.append(
            "Check the domain spelling and confirm it belongs to the organization you expect."
        )

    if any("DNS" in factor for factor in risk_factors):
        recommendations.append(
            "Check the domain spelling and try again later if the website is temporarily unavailable."
        )

    if any("SSL/TLS" in factor for factor in risk_factors):
        recommendations.append(
            "Do not enter sensitive information until the website's secure connection can be verified."
        )

    if any("redirect" in factor.lower() for factor in risk_factors):
        recommendations.append(
            "Review the redirect chain and verify the final domain independently before entering sensitive information."
        )

    if not recommendations:
        recommendations.append(
            "No basic URL-pattern warnings were detected. This does not guarantee that the website is safe."
        )

    if risk_level == "High":
        recommendations.append(
            "Treat this URL with caution and do not submit sensitive information until it has been verified."
        )
    elif risk_level == "Medium":
        recommendations.append(
            "Verify the website using an official source before signing in, paying, or sharing personal information."
        )

    print("DEBUG: Saving scan result to MySQL...")

    saved_to_database = save_scan_history(

        scanned_url=url,
        trust_score=trust_score,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        recommendations=recommendations,
    )
    print("DEBUG: Database save status:", saved_to_database)
    if not saved_to_database:
        print("Warning: Scan result was not saved to MySQL.")

    return {
        "url": url,
        "hostname": hostname,
        "status": "analyzed",
        "trust_score": trust_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "checks": checks,
        "redirect_analysis": redirect_analysis,
        "recommendations": recommendations,
        "message": (
            "Basic rule-based URL analysis completed. This preliminary result does not prove whether a website is safe."
        ),
    }
    saved_to_database = save_scan_history(
        scanned_url=url,
        trust_score=trust_score,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        recommendations=recommendations,
)

@app.get("/scan/history")
def get_scan_history():
    connection = None

    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "3307")),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "digital_trust_score"),
            connect_timeout=5,
            cursorclass=pymysql.cursors.DictCursor,
        )

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    id,
                    scanned_url,
                    trust_score,
                    risk_score,
                    risk_level,
                    risk_factors,
                    recommendations,
                    scanned_at
                FROM scan_history
                ORDER BY id DESC
                LIMIT 100
            """)

            records = cursor.fetchall()

        for record in records:
            for field in ("risk_factors", "recommendations"):
                value = record.get(field)

                if isinstance(value, str):
                    try:
                        record[field] = json.loads(value)
                    except json.JSONDecodeError:
                        record[field] = []

            if record.get("scanned_at"):
                record["scanned_at"] = record["scanned_at"].isoformat()

        return {"history": records}

    except Exception as error:
        print("Could not fetch scan history:", error)
        raise HTTPException(
            status_code=500,
            detail="Could not fetch scan history from the database.",
        )

    finally:
        if connection is not None:
            connection.close()

from pydantic import BaseModel

class SMSScanRequest(BaseModel):
    message: str

class EmailScanRequest(BaseModel):
    email_content: str

@app.post("/scan/sms")
def scan_sms(request: SMSScanRequest):
    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=400,
            detail="SMS message cannot be empty."
        )

    risk_factors = []
    recommendations = []
    message_lower = message.lower()

    suspicious_keywords = [
        "urgent",
        "verify your account",
        "account blocked",
        "account suspended",
        "click here",
        "claim your prize",
        "won a prize",
        "lottery",
        "otp",
        "bank details",
        "send money",
        "kyc expired",
        "update kyc",
        "password",
        "upi pin",
    ]

    for keyword in suspicious_keywords:
        if keyword in message_lower:
            risk_factors.append(
                f"Suspicious phrase detected: {keyword}"
            )

    if "http://" in message_lower or "https://" in message_lower:
        risk_factors.append("SMS contains a URL.")

    if any(char.isdigit() for char in message) and any(
        word in message_lower
        for word in ["bank", "otp", "upi", "account"]
    ):
        risk_factors.append(
            "Financial or account-related message contains numbers."
        )

    risk_score = min(len(risk_factors) * 20, 100)
    trust_score = 100 - risk_score

    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if risk_factors:
        recommendations.append(
            "Do not click suspicious links or share OTPs, passwords, or UPI PINs."
        )
        recommendations.append(
            "Verify the message with the organization using its official contact details."
        )
    else:
        recommendations.append(
            "No configured suspicious patterns were detected. "
            "This does not guarantee that the SMS is safe."
        )

    saved = save_scan_history(
        scanned_url=f"SMS: {message[:150]}",
        trust_score=trust_score,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        recommendations=recommendations,
    )
    print("SMS HISTORY SAVED:", saved)

    return {
        "message": message,
        "trust_score": trust_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "recommendations": recommendations,
    }
@app.post("/scan/email")
def scan_email(request: EmailScanRequest):
    email_content = request.email_content.strip()

    if not email_content:
        raise HTTPException(
            status_code=400,
            detail="Email content cannot be empty."
        )

    email_lower = email_content.lower()

    risk_factors = []
    recommendations = []

    # Suspicious phrases commonly found in phishing emails
    suspicious_keywords = [
        "urgent",
        "verify your account",
        "account blocked",
        "account suspended",
        "click here",
        "claim your prize",
        "won a prize",
        "lottery",
        "bank details",
        "send money",
        "kyc expired",
        "update kyc",
        "password expires",
        "reset your password",
        "confirm your identity",
        "limited time",
        "act immediately",
        "unauthorized login",
        "congratulations",
        "payment failed",
    ]

    for keyword in suspicious_keywords:
        if keyword in email_lower:
            risk_factors.append(
                f"Suspicious phrase detected: {keyword}"
            )

    # Check for URLs
    if "http://" in email_lower or "https://" in email_lower:
        risk_factors.append(
            "Email contains a URL. Verify the destination before opening it."
        )

    # Check for urgency
    urgency_words = [
        "immediately",
        "right now",
        "within 24 hours",
        "last warning",
    ]

    if any(word in email_lower for word in urgency_words):
        risk_factors.append(
            "Email uses urgency to encourage quick action."
        )

    # Calculate heuristic risk score
    risk_score = min(len(risk_factors) * 20, 100)
    trust_score = 100 - risk_score

    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if risk_factors:
        recommendations.append(
            "Do not click links or open attachments unless you verify the sender."
        )
        recommendations.append(
            "Never share passwords, OTPs, banking details, or UPI PINs by email."
        )
        recommendations.append(
            "Verify the sender using the organization's official website or contact details."
        )
    else:
        recommendations.append(
            "No configured suspicious patterns were detected. "
            "This does not guarantee that the email is safe."
        )

    # Save email scan to database history
    saved = save_scan_history(
        scanned_url=f"EMAIL: {email_content[:150]}",
        trust_score=trust_score,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        recommendations=recommendations,
    )

    print("EMAIL HISTORY SAVED:", saved)

    return {
        "email_content": email_content,
        "trust_score": trust_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "recommendations": recommendations,
    }
