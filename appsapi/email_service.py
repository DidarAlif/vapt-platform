"""
Email verification service for ReconScience.
Uses SMTP with TLS for secure email delivery.
Non-blocking with timeout handling.
"""
import os
import secrets
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional

# Email configuration from environment
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
# Strip spaces from password (Google App Passwords display with spaces)
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").replace(" ", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USER)
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "ReconScience")

# Skip email verification (set to "true" to auto-verify users)
SKIP_EMAIL_VERIFICATION = os.getenv("SKIP_EMAIL_VERIFICATION", "false").lower() == "true"

# Frontend URL for verification links
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Token settings
VERIFICATION_TOKEN_EXPIRE_HOURS = 24

# SMTP timeout in seconds
SMTP_TIMEOUT = 15

# Debug mode
DEBUG_SMTP = os.getenv("DEBUG_SMTP", "true").lower() == "true"


def generate_verification_token() -> str:
    """Generate a secure random verification token."""
    return secrets.token_urlsafe(32)


def get_token_expiry() -> datetime:
    """Get the expiry datetime for a new token."""
    return datetime.utcnow() + timedelta(hours=VERIFICATION_TOKEN_EXPIRE_HOURS)


def is_token_expired(sent_at: Optional[datetime]) -> bool:
    """Check if a verification token has expired."""
    if not sent_at:
        return True
    expiry = sent_at + timedelta(hours=VERIFICATION_TOKEN_EXPIRE_HOURS)
    return datetime.utcnow() > expiry


def should_skip_verification() -> bool:
    """Check if email verification should be skipped."""
    return SKIP_EMAIL_VERIFICATION


def _send_email_sync(to_email: str, subject: str, html_content: str, text_content: str):
    """Internal function to send email synchronously with timeout."""
    if DEBUG_SMTP:
        print(f"[Email Debug] Attempting to send email to {to_email}")
        print(f"[Email Debug] SMTP_HOST: {SMTP_HOST}")
        print(f"[Email Debug] SMTP_PORT: {SMTP_PORT}")
        print(f"[Email Debug] SMTP_USER: {SMTP_USER}")
        print(f"[Email Debug] SMTP_PASSWORD length: {len(SMTP_PASSWORD)} chars")
        print(f"[Email Debug] FROM: {SMTP_FROM_EMAIL}")
    
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg["To"] = to_email
        
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))
        
        if DEBUG_SMTP:
            print(f"[Email Debug] Connecting to {SMTP_HOST}:{SMTP_PORT}...")
        
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
            if DEBUG_SMTP:
                print(f"[Email Debug] Connected. Starting TLS...")
            server.starttls()
            if DEBUG_SMTP:
                print(f"[Email Debug] TLS started. Logging in...")
            server.login(SMTP_USER, SMTP_PASSWORD)
            if DEBUG_SMTP:
                print(f"[Email Debug] Logged in. Sending email...")
            server.sendmail(SMTP_FROM_EMAIL, to_email, msg.as_string())
        
        print(f"[Email] Successfully sent to {to_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"[Email ERROR] SMTP authentication failed: {e}")
        print(f"[Email ERROR] Check your SMTP_USER and SMTP_PASSWORD")
        return False
    except smtplib.SMTPConnectError as e:
        print(f"[Email ERROR] Could not connect to SMTP server: {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"[Email ERROR] SMTP error: {e}")
        return False
    except ConnectionRefusedError as e:
        print(f"[Email ERROR] Connection refused: {e}")
        return False
    except TimeoutError as e:
        print(f"[Email ERROR] Connection timed out: {e}")
        return False
    except Exception as e:
        print(f"[Email ERROR] Failed to send: {type(e).__name__}: {e}")
        return False



def _send_email_async(to_email: str, subject: str, html_content: str, text_content: str):
    """Send email in a background thread to avoid blocking."""
    thread = threading.Thread(
        target=_send_email_sync,
        args=(to_email, subject, html_content, text_content),
        daemon=True
    )
    thread.start()


def send_verification_email(to_email: str, to_name: str, token: str) -> bool:
    """
    Send email verification link to user.
    Sends asynchronously to avoid blocking the request.
    Returns True immediately (fire and forget).
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        print("[Email] SMTP credentials not configured, skipping email send")
        print(f"[Email] Verification token for {to_email}: {token}")
        print(f"[Email] Verify URL: {FRONTEND_URL}/verify-email?token={token}")
        return False
    
    verification_url = f"{FRONTEND_URL}/verify-email?token={token}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e5e5e5; padding: 40px; }}
            .container {{ max-width: 500px; margin: 0 auto; background: #12121a; border: 1px solid #1e1e2e; border-radius: 12px; padding: 32px; }}
            .logo {{ text-align: center; margin-bottom: 24px; font-size: 24px; font-weight: bold; color: #00d4aa; }}
            h1 {{ font-size: 20px; color: #ffffff; margin-bottom: 16px; }}
            p {{ color: #a0a0a0; line-height: 1.6; margin-bottom: 16px; }}
            .btn {{ display: inline-block; background: #00d4aa; color: #0a0a0f; text-decoration: none; padding: 12px 32px; border-radius: 8px; font-weight: 600; }}
            .footer {{ margin-top: 32px; padding-top: 24px; border-top: 1px solid #1e1e2e; font-size: 12px; color: #666; }}
            .code {{ background: #0a0a0f; padding: 8px 12px; border-radius: 4px; font-family: monospace; font-size: 12px; word-break: break-all; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">ReconScience</div>
            <h1>Verify Your Email</h1>
            <p>Hi {to_name},</p>
            <p>Thanks for signing up for ReconScience. Please verify your email address to start using the security scanning platform.</p>
            <p style="text-align: center; margin: 32px 0;">
                <a href="{verification_url}" class="btn">Verify Email Address</a>
            </p>
            <p>Or copy this link:</p>
            <p class="code">{verification_url}</p>
            <p>This link expires in 24 hours.</p>
            <div class="footer">
                <p>If you didn't create an account, you can safely ignore this email.</p>
                <p>© 2026 ReconScience. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = f"""
    ReconScience - Verify Your Email
    
    Hi {to_name},
    
    Thanks for signing up for ReconScience. Please verify your email address by clicking the link below:
    
    {verification_url}
    
    This link expires in 24 hours.
    
    If you didn't create an account, you can safely ignore this email.
    """
    
    # Send email in background thread
    _send_email_async(to_email, "Verify your ReconScience account", html_content, text_content)
    print(f"[Email] Verification email queued for {to_email}")
    return True


def send_password_reset_email(to_email: str, to_name: str, token: str) -> bool:
    """Send password reset link to user (async)."""
    if not SMTP_USER or not SMTP_PASSWORD:
        print("[Email] SMTP credentials not configured")
        return False
    
    reset_url = f"{FRONTEND_URL}/reset-password?token={token}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e5e5e5; padding: 40px; }}
            .container {{ max-width: 500px; margin: 0 auto; background: #12121a; border: 1px solid #1e1e2e; border-radius: 12px; padding: 32px; }}
            .logo {{ text-align: center; margin-bottom: 24px; font-size: 24px; font-weight: bold; color: #00d4aa; }}
            h1 {{ font-size: 20px; color: #ffffff; margin-bottom: 16px; }}
            p {{ color: #a0a0a0; line-height: 1.6; margin-bottom: 16px; }}
            .btn {{ display: inline-block; background: #00d4aa; color: #0a0a0f; text-decoration: none; padding: 12px 32px; border-radius: 8px; font-weight: 600; }}
            .footer {{ margin-top: 32px; padding-top: 24px; border-top: 1px solid #1e1e2e; font-size: 12px; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">ReconScience</div>
            <h1>Reset Your Password</h1>
            <p>Hi {to_name},</p>
            <p>We received a request to reset your password. Click the button below to create a new password.</p>
            <p style="text-align: center; margin: 32px 0;">
                <a href="{reset_url}" class="btn">Reset Password</a>
            </p>
            <p>This link expires in 1 hour.</p>
            <div class="footer">
                <p>If you didn't request this, you can safely ignore this email.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = f"Reset your password: {reset_url}"
    
    _send_email_async(to_email, "Reset your ReconScience password", html_content, text_content)
    return True
