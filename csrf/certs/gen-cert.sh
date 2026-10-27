#!/usr/bin/env bash
# Generates a self-signed TLS certificate for the victim app.
#
# Why this is needed:
#   The exploit only works if the victim's browser attaches the session cookie
#   to the attacker's CROSS-SITE POST. Modern browsers default cookies to
#   SameSite=Lax, which blocks that. So the victim app sets its cookie to
#   SameSite=None, and browsers only accept SameSite=None together with the
#   Secure flag, and Secure cookies require HTTPS. HTTPS on localhost needs a
#   certificate -- and since there is no public CA for localhost, we self-sign.
#
# The browser will show a one-time "self-signed / not secure" warning: accept it.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/key.pem" \
  -out    "$DIR/cert.pem" \
  -days   365 \
  -subj   "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Certificate written to:"
echo "  $DIR/key.pem"
echo "  $DIR/cert.pem"
