"""
Email verification service for ReconScience.
Uses Resend API for reliable email delivery.
"""
import os
import secrets
import resend
from datetime import datetime, timedelta
from typing import Optional

# Resend configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "ReconScience <onboarding@resend.dev>")

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


def _init_resend():
    """Initialize Resend with API key."""
    if RESEND_API_KEY:
        resend.api_key = RESEND_API_KEY
    else:
        print("[Email] WARNING: RESEND_API_KEY not set")


def send_verification_email(to_email: str, to_name: str, token: str) -> bool:
    """
    Send email verification link to user via Resend.
    Returns True on success, False on failure.
    """
    if not RESEND_API_KEY:
        print("[Email] RESEND_API_KEY not configured, skipping email send")
        print(f"[Email] Verification token for {to_email}: {token}")
        print(f"[Email] Verify URL: {FRONTEND_URL}/verify-email?token={token}")
        return False

    _init_resend()
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

    try:
        params = {
            "from": RESEND_FROM_EMAIL,
            "to": [to_email],
            "subject": "Verify your ReconScience account",
            "html": html_content,
        }

        email_response = resend.Emails.send(params)

        if DEBUG_EMAIL:
            print(f"[Email] Verification email sent to {to_email}: {email_response}")

        return True

    except Exception as e:
        print(f"[Email ERROR] Failed to send verification email: {type(e).__name__}: {e}")
        return False


def send_password_reset_email(to_email: str, to_name: str, token: str) -> bool:
    """Send password reset link to user via Resend."""
    if not RESEND_API_KEY:
        print("[Email] RESEND_API_KEY not configured")
        return False

    _init_resend()
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

    try:
        params = {
            "from": RESEND_FROM_EMAIL,
            "to": [to_email],
            "subject": "Reset your ReconScience password",
            "html": html_content,
        }

        resend.Emails.send(params)
        return True

    except Exception as e:
        print(f"[Email ERROR] Failed to send reset email: {type(e).__name__}: {e}")
        return False
