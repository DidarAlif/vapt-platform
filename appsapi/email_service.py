"""
Email verification service for ReconScience.
Uses SMTP with TLS for secure email delivery.
"""
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional

# Email configuration from environment
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USER)
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "ReconScience")

# Frontend URL for verification links
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Token settings
VERIFICATION_TOKEN_EXPIRE_HOURS = 24


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


def send_verification_email(to_email: str, to_name: str, token: str) -> bool:
    """
    Send email verification link to user.
    Returns True if email was sent successfully.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        print("[Email] SMTP credentials not configured, skipping email send")
        print(f"[Email] Verification token for {to_email}: {token}")
        return False
    
    verification_url = f"{FRONTEND_URL}/verify-email?token={token}"
    
    # Create HTML email
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
            .btn:hover {{ background: #00b894; }}
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
    
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Verify your ReconScience account"
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg["To"] = to_email
        
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))
        
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()  # Enable TLS
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM_EMAIL, to_email, msg.as_string())
        
        print(f"[Email] Verification email sent to {to_email}")
        return True
        
    except Exception as e:
        print(f"[Email] Failed to send verification email: {e}")
        return False


def send_password_reset_email(to_email: str, to_name: str, token: str) -> bool:
    """Send password reset link to user."""
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
    
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Reset your ReconScience password"
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg["To"] = to_email
        
        msg.attach(MIMEText(html_content, "html"))
        
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM_EMAIL, to_email, msg.as_string())
        
        return True
        
    except Exception as e:
        print(f"[Email] Failed to send password reset email: {e}")
        return False
