const router = require('express').Router();
const db = require('../db');
const verifyToken = require('../middleware/auth');
const crypto = require('crypto');
require('dotenv').config();

// Encryption settings
const ALGORITHM = 'aes-256-cbc';
// Ensure key is 32 bytes. If ENCRYPTION_KEY is string, we can hash it.
// For simplicity, we assume ENCRYPTION_KEY is a 32-char string or use a fallback mechanism.
// Better approach: create a 32-byte buffer from the secret.
const KEY = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'secret', 'salt', 32);

const encrypt = (text) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), content: encrypted };
};

const decrypt = (hash) => {
    const iv = Buffer.from(hash.iv, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
    let decrypted = decipher.update(hash.content, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

// Get all passwords for user
router.get('/', verifyToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM passwords WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);

        const passwords = result.rows.map(row => ({
            id: row.id,
            site_name: row.site_name,
            site_username: row.site_username,
            site_password: decrypt({ iv: row.iv, content: row.site_password_encrypted }),
            created_at: row.created_at
        }));

        res.json(passwords);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add new password
router.post('/', verifyToken, async (req, res) => {
    try {
        const { site_name, site_username, site_password } = req.body;

        if (!site_name || !site_password) {
            return res.status(400).json({ error: 'Site name and password are required' });
        }

        const encrypted = encrypt(site_password);

        const newPassword = await db.query(
            'INSERT INTO passwords (user_id, site_name, site_username, site_password_encrypted, iv) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [req.user.id, site_name, site_username, encrypted.content, encrypted.iv]
        );

        res.status(201).json({
            id: newPassword.rows[0].id,
            site_name,
            site_username,
            site_password, // Return unencrypted for immediate UI update
            created_at: newPassword.rows[0].created_at
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update password
router.put('/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { site_name, site_username, site_password } = req.body;

        if (!site_name || !site_password) {
            return res.status(400).json({ error: 'Site name and password are required' });
        }

        const encrypted = encrypt(site_password);

        const updatedPassword = await db.query(
            'UPDATE passwords SET site_name = $1, site_username = $2, site_password_encrypted = $3, iv = $4 WHERE id = $5 AND user_id = $6 RETURNING *',
            [site_name, site_username, encrypted.content, encrypted.iv, id, req.user.id]
        );

        if (updatedPassword.rows.length === 0) {
            return res.status(404).json({ error: 'Password entry not found or unauthorized' });
        }

        res.json({
            id: updatedPassword.rows[0].id,
            site_name,
            site_username,
            site_password,
            created_at: updatedPassword.rows[0].created_at
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
