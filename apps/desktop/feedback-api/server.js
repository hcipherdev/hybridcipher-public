/**
 * HybridCipher Feedback API Server
 * 
 * Receives feedback submissions from the desktop app and sends them via email.
 * 
 * Configuration (environment variables):
 *   SMTP_HOST      - SMTP server hostname
 *   SMTP_PORT      - SMTP port (default: 587)
 *   SMTP_SECURE    - Use TLS (default: false, set to "true" for port 465)
 *   SMTP_USER      - SMTP username
 *   SMTP_PASS      - SMTP password
 *   FEEDBACK_EMAIL - Email address to receive feedback
 *   PORT           - Server port (default: 3001)
 */

const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Allow large attachments

const PRODUCTION_TOML_PATH = process.env.HYBRIDCIPHER_CONFIG_PATH
    || path.resolve(__dirname, '../../../config/production.toml');

const stripInlineComment = (line) => {
    let inQuotes = false;
    let escaped = false;
    for (let i = 0; i < line.length; i += 1) {
        const char = line[i];
        if (char === '\\' && !escaped) {
            escaped = true;
            continue;
        }
        if (char === '"' && !escaped) {
            inQuotes = !inQuotes;
        }
        if (char === '#' && !inQuotes) {
            return line.slice(0, i).trim();
        }
        escaped = false;
    }
    return line.trim();
};

const parseTomlValue = (value) => {
    const trimmed = value.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
        return trimmed.slice(1, -1);
    }
    if (trimmed === 'true') return true;
    if (trimmed === 'false') return false;
    if (/^-?\d+$/.test(trimmed)) return parseInt(trimmed, 10);
    return trimmed;
};

const loadProductionSmtpConfig = () => {
    if (!fs.existsSync(PRODUCTION_TOML_PATH)) {
        return null;
    }

    try {
        const content = fs.readFileSync(PRODUCTION_TOML_PATH, 'utf8');
        const lines = content.split(/\r?\n/);
        let inSmtpSection = false;
        const smtp = {};

        for (const rawLine of lines) {
            const trimmed = rawLine.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;

            if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
                inSmtpSection = trimmed === '[feedback.smtp]';
                continue;
            }

            if (!inSmtpSection) continue;
            const cleanLine = stripInlineComment(trimmed);
            if (!cleanLine) continue;

            const match = cleanLine.match(/^([A-Za-z0-9_]+)\s*=\s*(.+)$/);
            if (!match) continue;
            smtp[match[1]] = parseTomlValue(match[2]);
        }

        return Object.keys(smtp).length > 0 ? smtp : null;
    } catch (error) {
        console.warn(`⚠ Failed to read SMTP config from ${PRODUCTION_TOML_PATH}: ${error.message}`);
        return null;
    }
};

const productionSmtp = loadProductionSmtpConfig();

const smtpPort = parseInt(
    process.env.SMTP_PORT || productionSmtp?.smtp_port || '587',
    10,
);
const smtpSecureEnv = process.env.SMTP_SECURE;
const smtpUseTls = productionSmtp?.use_tls === true;
const smtpSecure = smtpSecureEnv ? smtpSecureEnv === 'true' : smtpPort === 465;
const requireTls = !smtpSecureEnv && smtpUseTls;

// Configuration with placeholders + production.toml fallback
const config = {
    port: process.env.PORT || 3001,
    smtp: {
        host: process.env.SMTP_HOST || productionSmtp?.smtp_host || 'YOUR_SMTP_HOST',
        port: smtpPort,
        secure: smtpSecure,
        auth: {
            user: process.env.SMTP_USER || productionSmtp?.username || 'YOUR_SMTP_USER',
            pass: process.env.SMTP_PASS || productionSmtp?.password || 'YOUR_SMTP_PASS',
        },
    },
    smtpFrom: {
        address: process.env.SMTP_FROM_ADDRESS || productionSmtp?.from_address || null,
        name: process.env.SMTP_FROM_NAME || productionSmtp?.from_name || null,
    },
    feedbackEmail: process.env.FEEDBACK_EMAIL
        || productionSmtp?.from_address
        || 'feedback@hybridcipher.com',
    smtpConfigSource: productionSmtp ? PRODUCTION_TOML_PATH : 'environment',
};

if (requireTls) {
    config.smtp.requireTLS = true;
}

// Create mail transporter
const transporter = nodemailer.createTransport(config.smtp);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Feedback submission endpoint
app.post('/feedback', async (req, res) => {
    try {
        const { title, description, user_email, attachments, app_version, platform } = req.body;

        // Validate required fields
        if (!title || !description) {
            return res.status(400).json({
                success: false,
                message: 'Title and description are required',
            });
        }

        console.log(`[${new Date().toISOString()}] Received feedback: "${title}" from ${user_email || 'anonymous'}`);
        console.log(`  Platform: ${platform}, Version: ${app_version}, Attachments: ${attachments?.length || 0}`);

        // Build email content
        const emailBody = `
New Feedback Submission
========================

Title: ${title}

From: ${user_email || 'Anonymous'}
Platform: ${platform || 'Unknown'}
App Version: ${app_version || 'Unknown'}
Time: ${new Date().toISOString()}

Description:
------------
${description}

---
Sent from HybridCipher Desktop App
        `.trim();

        // Prepare attachments for nodemailer
        const mailAttachments = (attachments || []).map((att, index) => ({
            filename: att.filename || `attachment-${index + 1}`,
            content: Buffer.from(att.content_base64, 'base64'),
            contentType: att.mime_type || 'application/octet-stream',
        }));

        // Check if SMTP is configured (not placeholders)
        const smtpConfigured = config.smtp.host !== 'YOUR_SMTP_HOST' &&
            config.smtp.auth.user !== 'YOUR_SMTP_USER' &&
            config.smtp.auth.pass !== 'YOUR_SMTP_PASS';

        if (smtpConfigured) {
            const fromAddress = config.smtpFrom.address || config.smtp.auth.user;
            const fromName = config.smtpFrom.name || 'HybridCipher Feedback';
            // Send email
            await transporter.sendMail({
                from: `"${fromName}" <${fromAddress}>`,
                to: config.feedbackEmail,
                replyTo: user_email || undefined,
                subject: `[Feedback] ${title}`,
                text: emailBody,
                attachments: mailAttachments,
            });

            console.log(`  ✓ Email sent to ${config.feedbackEmail}`);
        } else {
            // SMTP not configured - just log the feedback
            console.log('  ⚠ SMTP not configured - email not sent');
            console.log('  Email would have been:');
            console.log(`  To: ${config.feedbackEmail}`);
            console.log(`  Subject: [Feedback] ${title}`);
            console.log(`  Body:\n${emailBody}`);
            if (mailAttachments.length > 0) {
                console.log(`  Attachments: ${mailAttachments.map(a => a.filename).join(', ')}`);
            }
        }

        res.json({ success: true, message: 'Feedback received' });

    } catch (error) {
        console.error('Failed to process feedback:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to process feedback',
        });
    }
});

// Start server
app.listen(config.port, () => {
    console.log(`\n╔════════════════════════════════════════════╗`);
    console.log(`║  HybridCipher Feedback API                 ║`);
    console.log(`╠════════════════════════════════════════════╣`);
    console.log(`║  Listening on port ${config.port}                    ║`);
    console.log(`╚════════════════════════════════════════════╝\n`);

    if (productionSmtp) {
        console.log(`SMTP config loaded from ${config.smtpConfigSource}`);
    }

    if (config.smtp.host === 'YOUR_SMTP_HOST') {
        console.log('⚠  SMTP is not configured. Set these environment variables:');
        console.log('   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, FEEDBACK_EMAIL');
        console.log(`   Or set [feedback.smtp] in ${config.smtpConfigSource}\n`);
        console.log('   Feedback will be logged to console until SMTP is configured.\n');
    }
});
