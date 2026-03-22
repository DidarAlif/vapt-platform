"""
Email verification service for ReconScience.
Uses SMTP (Gmail) for reliable and free email delivery.
"""
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional

# SMTP configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "alifmddidarulalam@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")  # Google App Password
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "ReconScience <alifmddidarulalam@gmail.com>")

# Frontend URL for verification links
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Token settings
VERIFICATION_TOKEN_EXPIRE_HOURS = 24

# Debug mode
DEBUG_EMAIL = os.getenv("DEBUG_EMAIL", "true").lower() == "true"


def generate_verification_token() -> str:
    """Generate a secure 6-digit verification OTP."""
    return "".join([str(secrets.randbelow(10)) for _ in range(6)])


def get_token_expiry() -> datetime:
    """Get the expiry datetime for a new token."""
    return datetime.utcnow() + timedelta(hours=VERIFICATION_TOKEN_EXPIRE_HOURS)


def is_token_expired(sent_at: Optional[datetime]) -> bool:
    """Check if a verification token has expired."""
    if not sent_at:
        return True
    expiry = sent_at + timedelta(hours=VERIFICATION_TOKEN_EXPIRE_HOURS)
    return datetime.utcnow() > expiry


def _send_email_smtp(to_email: str, subject: str, html_content: str) -> bool:
    """Internal helper to send an email via SMTP."""
    if not SMTP_PASSWORD:
        print("[Email] SMTP_PASSWORD not configured, skipping email send")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM_EMAIL
        msg["To"] = to_email

        # Attach the HTML content
        part = MIMEText(html_content, "html")
        msg.attach(part)

        # Connect to Gmail SMTP server
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, msg.as_string())
        server.quit()
        
        return True
    except Exception as e:
        print(f"[Email ERROR] Failed to send email via SMTP: {type(e).__name__}: {e}")
        return False


def send_verification_email(to_email: str, to_name: str, token: str) -> bool:
    """
    Send email verification link to user via SMTP.
    Returns True on success, False on failure.
    """
    if not SMTP_PASSWORD:
        print("[Email] SMTP_PASSWORD not configured, skipping email send")
        print(f"[Email] Verification token for {to_email}: {token}")
        print(f"[Email] Verify URL: {FRONTEND_URL}/verify-email?token={token}")
        return False

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
            <p>Thanks for signing up for ReconScience. Please use the following OTP to verify your email address:</p>
            <div style="text-align: center; margin: 32px 0;">
                <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #00d4aa; background: #0a0a0f; padding: 16px 24px; border-radius: 8px; display: inline-block;">
                    {token}
                </div>
            </div>
            <p>This OTP expires in 24 hours.</p>
            <div class="footer">
                <p>If you didn't create an account, you can safely ignore this email.</p>
                <p>&copy; 2026 ReconScience. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """

    success = _send_email_smtp(to_email, "Verify your ReconScience account", html_content)
    
    if success and DEBUG_EMAIL:
        print(f"[Email] Verification email sent to {to_email}")
        
    return success


def send_password_reset_email(to_email: str, to_name: str, token: str) -> bool:
    """Send password reset link to user via SMTP."""
    if not SMTP_PASSWORD:
        print("[Email] SMTP_PASSWORD not configured")
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

    success = _send_email_smtp(to_email, "Reset your ReconScience password", html_content)
    return success

