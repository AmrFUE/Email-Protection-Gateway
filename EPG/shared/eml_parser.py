"""
eml_parser.py - Email Attachment Extractor
==========================================
Parses raw .eml files and extracts all attachments for scanning.
Used by the malware scanner API to process emails from the EPG pipeline.

Usage:
    from eml_parser import extract_attachments
    
    attachments = extract_attachments("/path/to/email.eml")
    for att in attachments:
        print(att['filename'], att['content_type'], att['path'])
"""

import os
import email
import email.policy
import tempfile
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("EMLParser")


def extract_attachments(eml_path: str, output_dir: Optional[str] = None) -> list[dict]:
    """
    Parse an .eml file and extract all attachments to disk.
    
    Args:
        eml_path: Path to the .eml file
        output_dir: Directory to save extracted files. If None, uses a temp dir.
    
    Returns:
        List of dicts with keys: filename, path, content_type, size, hash
    """
    if not os.path.exists(eml_path):
        raise FileNotFoundError(f"EML file not found: {eml_path}")

    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    # Extract email metadata
    metadata = {
        'from': str(msg.get('From', '')),
        'to': str(msg.get('To', '')),
        'subject': str(msg.get('Subject', '')),
        'date': str(msg.get('Date', '')),
        'message_id': str(msg.get('Message-ID', '')),
    }

    # Create output directory
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="epg_attachments_")
    else:
        os.makedirs(output_dir, exist_ok=True)

    attachments = []

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        content_type = part.get_content_type()

        # Skip text/html body parts (not attachments)
        if part.get_content_maintype() == 'multipart':
            continue

        # Check if this part is an attachment
        is_attachment = (
            "attachment" in content_disposition
            or "inline" in content_disposition
            or content_type not in ('text/plain', 'text/html')
        )

        if not is_attachment:
            continue

        # Get filename
        filename = part.get_filename()
        if not filename:
            # Generate a name for unnamed attachments
            ext = _guess_extension(content_type)
            filename = f"unnamed_attachment{ext}"

        # Sanitize filename (prevent path traversal)
        filename = _sanitize_filename(filename)

        # Get content
        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        # Save to disk
        file_path = os.path.join(output_dir, filename)

        # Handle duplicate filenames
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(file_path):
            file_path = os.path.join(output_dir, f"{base}_{counter}{ext}")
            counter += 1

        with open(file_path, 'wb') as f:
            f.write(payload)

        # Compute hash
        sha256 = hashlib.sha256(payload).hexdigest()

        attachments.append({
            'filename': os.path.basename(file_path),
            'path': file_path,
            'content_type': content_type,
            'size': len(payload),
            'hash': sha256,
        })

        logger.info(f"Extracted: {filename} ({content_type}, {len(payload):,} bytes)")

    return attachments, metadata


def extract_body(eml_path: str) -> dict:
    """
    Extract the email body text (plain and HTML) for spam/phishing analysis.
    
    Returns:
        Dict with keys: plain_text, html_text, urls
    """
    import re

    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    plain_text = ""
    html_text = ""

    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain':
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or 'utf-8'
                try:
                    plain_text += payload.decode(charset, errors='replace')
                except Exception:
                    plain_text += payload.decode('utf-8', errors='replace')

        elif content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or 'utf-8'
                try:
                    html_text += payload.decode(charset, errors='replace')
                except Exception:
                    html_text += payload.decode('utf-8', errors='replace')

    # Extract URLs from both plain text and HTML
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    urls = list(set(
        url_pattern.findall(plain_text) + url_pattern.findall(html_text)
    ))

    return {
        'plain_text': plain_text,
        'html_text': html_text,
        'urls': urls,
    }


def extract_headers(eml_path: str) -> dict:
    """
    Extract email headers for spam/phishing analysis.
    Includes SPF, DKIM, DMARC results if present.
    """
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    headers = {
        'from': str(msg.get('From', '')),
        'to': str(msg.get('To', '')),
        'reply_to': str(msg.get('Reply-To', '')),
        'subject': str(msg.get('Subject', '')),
        'date': str(msg.get('Date', '')),
        'message_id': str(msg.get('Message-ID', '')),
        'return_path': str(msg.get('Return-Path', '')),
        'x_mailer': str(msg.get('X-Mailer', '')),
    }

    # Collect all Received headers (trace the email path)
    received = msg.get_all('Received', [])
    headers['received_chain'] = [str(r) for r in received]
    headers['hop_count'] = len(received)

    # Authentication results
    auth_results = str(msg.get('Authentication-Results', ''))
    headers['authentication_results'] = auth_results
    headers['spf_pass'] = 'spf=pass' in auth_results.lower()
    headers['dkim_pass'] = 'dkim=pass' in auth_results.lower()
    headers['dmarc_pass'] = 'dmarc=pass' in auth_results.lower()

    return headers


def _sanitize_filename(filename: str) -> str:
    """Remove path separators and dangerous characters from filename."""
    # Remove any path components
    filename = os.path.basename(filename)
    # Remove null bytes and path separators
    dangerous = ['/', '\\', '\x00', '..', '~']
    for char in dangerous:
        filename = filename.replace(char, '_')
    # Limit length
    if len(filename) > 200:
        base, ext = os.path.splitext(filename)
        filename = base[:195] + ext
    return filename or "unnamed_file"


def _guess_extension(content_type: str) -> str:
    """Guess file extension from content type."""
    mapping = {
        'application/pdf': '.pdf',
        'application/msword': '.doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
        'application/vnd.ms-excel': '.xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
        'application/vnd.ms-powerpoint': '.ppt',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
        'application/zip': '.zip',
        'application/x-rar-compressed': '.rar',
        'application/x-7z-compressed': '.7z',
        'application/x-msdownload': '.exe',
        'application/x-dosexec': '.exe',
        'application/rtf': '.rtf',
        'image/png': '.png',
        'image/jpeg': '.jpg',
    }
    return mapping.get(content_type, '.bin')
