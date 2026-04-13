#!/bin/sh
set -e

# Variables (adjust as needed)
PROJECT_ID="default"
READER_EMAIL="reader@dataminded.com"
ADMIN_EMAIL="admin@dataminded.com"
READER_PASSWORD="reader123"
ADMIN_PASSWORD="admin123"

# Create groups if they don't exist
zitadel org member add --org $PROJECT_ID --user $READER_EMAIL --roles reader || true
zitadel org member add --org $PROJECT_ID --user $ADMIN_EMAIL --roles admin || true

# Create users
zitadel user human add --username $READER_EMAIL --firstname Reader --lastname User --email $READER_EMAIL --password $READER_PASSWORD || true
zitadel user human add --username $ADMIN_EMAIL --firstname Admin --lastname User --email $ADMIN_EMAIL --password $ADMIN_PASSWORD || true

# Assign users to groups
zitadel org member add --org $PROJECT_ID --user $READER_EMAIL --roles reader
zitadel org member add --org $PROJECT_ID --user $ADMIN_EMAIL --roles admin

echo "Users and groups created."
