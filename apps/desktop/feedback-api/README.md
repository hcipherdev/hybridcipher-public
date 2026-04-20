# HybridCipher Feedback API

Optional Node.js service used by the desktop app to receive feedback submissions and forward them by email.

It exposes a health endpoint and a feedback endpoint, accepts JSON bodies up to 50 MB, and falls back to console logging when SMTP is not configured.

## Requirements

- Node.js 18 or newer
- npm

## Quick Start

```bash
cd apps/desktop/feedback-api
npm install
npm start
```

The server listens on port `3001` by default.

## Configuration sources

The server resolves SMTP settings in this order:

1. Environment variables
2. `[feedback.smtp]` values loaded from `HYBRIDCIPHER_CONFIG_PATH`
3. Placeholder values that keep the service in console-log mode

## Environment variables

Set these environment variables before starting:

| Variable | Description | Example |
|----------|-------------|---------|
| `HYBRIDCIPHER_CONFIG_PATH` | Optional path to a TOML file containing a `[feedback.smtp]` section | `/etc/hybridcipher/production.toml` |
| `SMTP_HOST` | SMTP server hostname | `smtp.sendgrid.net` |
| `SMTP_PORT` | SMTP port (default: 587) | `587` |
| `SMTP_SECURE` | Use TLS (for port 465) | `true` |
| `SMTP_USER` | SMTP username | `apikey` |
| `SMTP_PASS` | SMTP password/API key | `SG.xxxx...` |
| `SMTP_FROM_ADDRESS` | Optional From email address override | `noreply@hybridcipher.com` |
| `SMTP_FROM_NAME` | Optional From display name override | `HybridCipher Feedback` |
| `FEEDBACK_EMAIL` | Recipient email | `beta@hybridcipher.com` |
| `PORT` | Server port | `3001` |

### Example with SendGrid

```bash
cd apps/desktop/feedback-api
export SMTP_HOST=smtp.sendgrid.net
export SMTP_PORT=587
export SMTP_USER=apikey
export SMTP_PASS=SG.your-api-key-here
export FEEDBACK_EMAIL=feedback@hybridcipher.com
npm start
```

### Example with Gmail

```bash
cd apps/desktop/feedback-api
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=your@gmail.com
export SMTP_PASS=your-app-password
export FEEDBACK_EMAIL=feedback@hybridcipher.com
npm start
```

## API Endpoints

### `GET /health`
Returns a simple health payload:

```json
{
  "status": "ok",
  "timestamp": "2026-04-02T12:34:56.000Z"
}
```

### `POST /feedback`
Submit feedback. `title` and `description` are required. The other fields are optional.

Request body:

```json
{
  "title": "Bug report",
  "description": "Detailed description...",
  "user_email": "user@example.com",
  "app_version": "0.1.0",
  "platform": "macos",
  "attachments": [
    {
      "filename": "screenshot.png",
      "content_base64": "iVBORw0KGgo...",
      "mime_type": "image/png"
    }
  ]
}
```

## Development Mode

Without valid SMTP credentials, the server accepts feedback and logs the rendered email payload to the console instead of sending mail. This makes local testing possible without a live mail service.

## Deployment

Before exposing this service publicly, add the controls that are not present in `server.js` today:

1. Put it behind a trusted reverse proxy or API gateway.
2. Add rate limiting.
3. Add authentication or API key validation.
4. Run it under a process manager such as `systemd` or PM2.
