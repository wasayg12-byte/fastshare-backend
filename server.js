const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const { createMessage, isConversationMessage } = require('./models');

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

const userIndexPath = path.join(__dirname, 'users.json');
const messageIndexPath = path.join(__dirname, 'messages.json');
const authSecretPath = path.join(__dirname, '.auth-secret');
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
const DOWNLOAD_TICKET_DURATION_MS = 5 * 60 * 1000;
const MAX_FILE_SIZE = 3 * 1024 ** 3;
const MAX_AVATAR_SIZE = 5 * 1024 * 1024;
const avatarDirectory = path.join(__dirname, 'avatars');
const avatarExtensions = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/webp': '.webp',
    'image/avif': '.avif',
};
fs.mkdirSync(avatarDirectory, { recursive: true });

let authSecret = process.env.AUTH_SECRET;
if (!authSecret) {
    try {
        authSecret = fs.readFileSync(authSecretPath, 'utf8');
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        authSecret = crypto.randomBytes(48).toString('hex');
        fs.writeFileSync(authSecretPath, authSecret, { mode: 0o600, flag: 'wx' });
    }
}

function signToken(payload) {
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', authSecret).update(encodedPayload).digest('base64url');
    return `${encodedPayload}.${signature}`;
}

function verifyToken(token) {
    if (typeof token !== 'string') return null;
    const [encodedPayload, signature, extra] = token.split('.');
    if (!encodedPayload || !signature || extra) return null;
    const expectedSignature = crypto.createHmac('sha256', authSecret).update(encodedPayload).digest();
    let submittedSignature;
    try {
        submittedSignature = Buffer.from(signature, 'base64url');
    } catch {
        return null;
    }
    if (expectedSignature.length !== submittedSignature.length || !crypto.timingSafeEqual(expectedSignature, submittedSignature)) return null;

    try {
        const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
        return payload.expiresAt > Date.now() ? payload : null;
    } catch {
        return null;
    }
}

function createSession(user) {
    return signToken({ phone: user.phone, expiresAt: Date.now() + SESSION_DURATION_MS, purpose: 'session' });
}

function requireSession(req, res, next) {
    const authorization = req.get('Authorization') || '';
    const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    const session = verifyToken(token);
    if (!session || session.purpose !== 'session') {
        return res.status(401).json({ success: false, message: 'Please sign in again.' });
    }

    const user = usersDatabase.find((entry) => entry.phone === session.phone);
    if (!user) return res.status(401).json({ success: false, message: 'Account not found. Please sign in again.' });
    req.authenticatedUser = user;
    next();
}

function normalizePhone(value) {
    if (typeof value !== 'string') return '';
    return value.trim();
}

function normalizeEmail(value) {
    if (typeof value !== 'string') return '';
    return value.trim().toLowerCase();
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function persistUsers(users) {
    const temporaryIndexPath = `${userIndexPath}.tmp`;
    fs.writeFileSync(temporaryIndexPath, JSON.stringify(users), { mode: 0o600 });
    fs.renameSync(temporaryIndexPath, userIndexPath);
}

function persistMessages(messages) {
    const temporaryIndexPath = `${messageIndexPath}.tmp`;
    fs.writeFileSync(temporaryIndexPath, JSON.stringify(messages), { mode: 0o600 });
    fs.renameSync(temporaryIndexPath, messageIndexPath);
}

let usersDatabase;
try {
    usersDatabase = JSON.parse(fs.readFileSync(userIndexPath, 'utf8'));
} catch (error) {
    if (error.code !== 'ENOENT') throw error;
    usersDatabase = [];
    persistUsers(usersDatabase);
}

let messagesDatabase;
try {
    messagesDatabase = JSON.parse(fs.readFileSync(messageIndexPath, 'utf8'));
} catch (error) {
    if (error.code !== 'ENOENT') throw error;
    messagesDatabase = [];
    persistMessages(messagesDatabase);
}

const uploadDirectory = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const transferIndexPath = path.join(uploadDirectory, 'transfers.json');
const frontendDirectory = process.env.FRONTEND_DIST_DIR;
fs.mkdirSync(uploadDirectory, { recursive: true });

if (frontendDirectory) {
    app.use(express.static(frontendDirectory));
}

const storage = multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, uploadDirectory),
    filename: (_req, _file, callback) => callback(null, crypto.randomUUID()),
});
const upload = multer({
    storage,
    limits: { fileSize: MAX_FILE_SIZE, files: 1 },
});
const avatarUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_AVATAR_SIZE, files: 1 },
    fileFilter: (_req, file, callback) => callback(null, Boolean(avatarExtensions[file.mimetype])),
});

function publicUser(user) {
    return {
        name: user.name,
        email: user.email,
        phone: user.phone,
        avatarUrl: user.avatarId ? `/api/profile/avatar/${user.avatarId}` : null,
    };
}

let transfers = new Map();
try {
    const savedTransfers = JSON.parse(fs.readFileSync(transferIndexPath, 'utf8'));
    transfers = new Map(savedTransfers.map((transfer) => [transfer.id, transfer]));
} catch (error) {
    if (error.code !== 'ENOENT') {
        console.error('Could not load saved transfer index:', error.message);
    }
}

function saveTransfer(transfer) {
    transfers.set(transfer.id, transfer);
    const temporaryIndexPath = `${transferIndexPath}.tmp`;
    fs.writeFileSync(temporaryIndexPath, JSON.stringify([...transfers.values()]), { mode: 0o600 });
    fs.renameSync(temporaryIndexPath, transferIndexPath);
}

// 🌍 Base Route
app.get('/', (req, res) => {
    res.send('FastShare Backend Server is Running Perfectly!');
});

// 👤 1. SIGNUP ROUTE (Account Creation)
app.post('/api/auth/signup', (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const phone = normalizePhone(req.body?.phone);

    if (!name || !email || !password || !phone) {
        return res.status(400).json({ success: false, message: "Please fill all fields (Name, Email, Password, Phone)" });
    }

    // Check if number or email already exists
    const userExists = usersDatabase.find((user) => user.phone === phone || normalizeEmail(user.email) === email);
    if (userExists) {
        return res.status(400).json({ success: false, message: "Email or Phone Number already registered!" });
    }

    // Save new user
    const newUser = { name, email, passwordHash: hashPassword(password), phone };
    const updatedUsers = [...usersDatabase, newUser];
    try {
        persistUsers(updatedUsers);
        usersDatabase = updatedUsers;
    } catch (error) {
        console.error('Could not save new user:', error.message);
        return res.status(500).json({ success: false, message: 'Could not save your account. Please try again.' });
    }
    
    console.log(`👤 New User Registered: ${name} (${phone})`);
    res.status(201).json({
        success: true,
        message: 'Account created successfully!',
        user: publicUser(newUser),
        token: createSession(newUser),
    });
});

// 🔐 2. LOGIN ROUTE
app.post('/api/auth/login', (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    const user = usersDatabase.find((entry) => normalizeEmail(entry.email) === email);
    if (!user || !user.passwordHash) {
        return res.status(401).json({ success: false, message: 'Email or password is incorrect.' });
    }

    const [salt, storedHash] = user.passwordHash.split(':');
    if (!salt || !storedHash) {
        return res.status(401).json({ success: false, message: 'Email or password is incorrect.' });
    }
    const submittedHash = crypto.scryptSync(password, salt, 64);
    const expectedHash = Buffer.from(storedHash, 'hex');
    if (submittedHash.length !== expectedHash.length || !crypto.timingSafeEqual(submittedHash, expectedHash)) {
        return res.status(401).json({ success: false, message: 'Email or password is incorrect.' });
    }

    res.json({
        success: true,
        message: 'Signed in successfully.',
        user: publicUser(user),
        token: createSession(user),
    });
});

// 🖼️ PROFILE PHOTO UPLOAD
app.post('/api/profile/avatar', requireSession, (req, res) => {
    avatarUpload.single('avatar')(req, res, (error) => {
        if (error) {
            const status = error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
            return res.status(status).json({ success: false, message: status === 413 ? 'Profile photos must be 5 MB or smaller.' : 'Choose a JPEG, PNG, WebP, or AVIF image.' });
        }
        if (!req.file) return res.status(400).json({ success: false, message: 'Choose a supported image.' });

        const avatarId = crypto.randomUUID();
        const avatarPath = path.join(avatarDirectory, `${avatarId}${avatarExtensions[req.file.mimetype]}`);
        const updatedUsers = usersDatabase.map((user) => user.phone === req.authenticatedUser.phone
            ? { ...user, avatarId, avatarMimeType: req.file.mimetype }
            : user);

        try {
            fs.writeFileSync(avatarPath, req.file.buffer, { mode: 0o600, flag: 'wx' });
            persistUsers(updatedUsers);
            usersDatabase = updatedUsers;
        } catch (saveError) {
            if (fs.existsSync(avatarPath)) fs.unlinkSync(avatarPath);
            console.error('Could not save profile photo:', saveError.message);
            return res.status(500).json({ success: false, message: 'Could not save this profile photo.' });
        }

        if (req.authenticatedUser.avatarId) {
            const previousExtension = avatarExtensions[req.authenticatedUser.avatarMimeType];
            const previousPath = previousExtension && path.join(avatarDirectory, `${req.authenticatedUser.avatarId}${previousExtension}`);
            if (previousPath && fs.existsSync(previousPath)) fs.unlinkSync(previousPath);
        }

        const updatedUser = updatedUsers.find((user) => user.phone === req.authenticatedUser.phone);
        res.json({ success: true, user: publicUser(updatedUser) });
    });
});

app.get('/api/profile/avatar/:avatarId', (req, res) => {
    const user = usersDatabase.find((entry) => entry.avatarId === req.params.avatarId);
    const extension = user && avatarExtensions[user.avatarMimeType];
    if (!user || !extension) return res.status(404).send('Profile photo not found.');
    res.set('Cache-Control', 'public, max-age=3600, immutable');
    res.type(user.avatarMimeType).sendFile(path.join(avatarDirectory, `${user.avatarId}${extension}`));
});

// 🔍 3. CONTACT CHECK ROUTE (WhatsApp Style Discovery)
app.post('/api/users/check-number', requireSession, (req, res) => {
    const phone = normalizePhone(req.body?.phone);

    if (!phone) {
        return res.status(400).json({ success: false, message: "Phone number is required" });
    }

    // Search database for the number
    const foundUser = usersDatabase.find((user) => user.phone === phone);

    if (foundUser) {
        // WhatsApp style response in English as requested
        return res.json({ 
            success: true, 
            status: "REGISTERED",
            message: `Verified User: You can message ${foundUser.name}`,
            user: publicUser(foundUser),
        });
    } else {
        return res.status(444).json({ 
            success: false, 
            status: "NOT_FOUND",
            message: "This number is not on the app yet. Invite them!" 
        });
    }
});

// 💬 4. CONVERSATION CONTACTS
app.get('/api/chat/conversations', requireSession, (req, res) => {
    const latestMessages = new Map();
    for (const message of messagesDatabase) {
        if (message.senderPhone !== req.authenticatedUser.phone && message.receiverPhone !== req.authenticatedUser.phone) continue;
        const phone = message.senderPhone === req.authenticatedUser.phone ? message.receiverPhone : message.senderPhone;
        const current = latestMessages.get(phone);
        if (!current || current.timestamp < message.timestamp) latestMessages.set(phone, message);
    }

    const conversations = [...latestMessages.entries()].map(([phone, message]) => {
        const contact = usersDatabase.find((user) => user.phone === phone);
        return {
            phone,
            name: contact?.name || phone,
            avatarUrl: contact?.avatarId ? `/api/profile/avatar/${contact.avatarId}` : null,
            latestMessage: message.textContent || (message.fileUrl ? 'Shared a file' : ''),
            timestamp: message.timestamp,
        };
    }).sort((left, right) => right.timestamp.localeCompare(left.timestamp));

    res.json({ success: true, conversations });
});

// 💬 5. SEND A TEXT MESSAGE
app.post('/api/chat/send-message', requireSession, (req, res) => {
    const receiverPhone = normalizePhone(req.body?.receiverPhone);
    const textContent = typeof req.body?.textContent === 'string' ? req.body.textContent : '';
    if (!receiverPhone) {
        return res.status(400).json({ success: false, message: 'A recipient phone number is required.' });
    }
    if (receiverPhone === req.authenticatedUser.phone) {
        return res.status(400).json({ success: false, message: 'You cannot send a message to yourself.' });
    }
    const receiver = usersDatabase.find((user) => user.phone === receiverPhone);
    if (!receiver) {
        return res.status(404).json({ success: false, message: 'This number is not registered on FastShare.' });
    }

    let message;
    try {
        message = createMessage({
            senderPhone: req.authenticatedUser.phone,
            receiverPhone,
            textContent,
        });
    } catch (error) {
        return res.status(400).json({ success: false, message: error.message });
    }

    const updatedMessages = [...messagesDatabase, message];
    try {
        persistMessages(updatedMessages);
        messagesDatabase = updatedMessages;
    } catch (error) {
        console.error('Could not save message:', error.message);
        return res.status(500).json({ success: false, message: 'Could not save your message. Please retry.' });
    }

    res.status(201).json({ success: true, message });
});

// 💬 6. FETCH A PRIVATE CONVERSATION HISTORY
app.get('/api/chat/get-messages', requireSession, (req, res) => {
    const user1 = normalizePhone(req.query.user1);
    const user2 = normalizePhone(req.query.user2);
    if (!user1 || user1 !== req.authenticatedUser.phone) {
        return res.status(403).json({ success: false, message: 'You can only view your own conversations.' });
    }
    if (!user2 || !usersDatabase.some((user) => user.phone === user2)) {
        return res.status(404).json({ success: false, message: 'This number is not registered on FastShare.' });
    }

    const publicApiUrl = (process.env.PUBLIC_API_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
    const conversation = messagesDatabase
        .filter((message) => isConversationMessage(message, user1, user2))
        .sort((left, right) => left.timestamp.localeCompare(right.timestamp))
        .map((message) => {
            if (!message.fileUrl) return message;
            const transferId = message.fileUrl.match(/^\/api\/transfers\/([a-f0-9]+)\/download$/)?.[1];
            const transfer = transferId ? transfers.get(transferId) : null;
            if (!transfer) return { ...message, fileUrl: null };
            const ticket = signToken({
                phone: req.authenticatedUser.phone,
                transferId,
                expiresAt: Date.now() + DOWNLOAD_TICKET_DURATION_MS,
                purpose: 'download',
            });
            return { ...message, fileUrl: `${publicApiUrl}/api/transfers/${transferId}/download?ticket=${ticket}`, fileName: transfer.fileName, fileSize: transfer.fileSize };
        });
    res.json({ success: true, messages: conversation });
});

// 📤 7. FILE TRANSFER ROUTE
app.post('/api/transfers', requireSession, (req, res, next) => {
    const recipientPhone = normalizePhone(req.get('X-Recipient-Phone'));
    const recipient = usersDatabase.find((user) => user.phone === recipientPhone);
    if (!recipientPhone || !recipient) {
        return res.status(404).json({ success: false, message: 'The recipient is not registered on FastShare.' });
    }
    req.transferRecipient = recipient;

    upload.single('file')(req, res, (error) => {
        if (!error) return next();
        if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ success: false, message: 'Files must be 3 GB or smaller.' });
        }
        return res.status(400).json({ success: false, message: error.message || 'Could not receive this file.' });
    });
}, (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Choose a file to send.' });
    }

    const transfer = {
        id: crypto.randomBytes(32).toString('hex'),
        fileName: path.basename(req.file.originalname),
        fileSize: req.file.size,
        storedName: req.file.filename,
        recipientPhone: req.transferRecipient.phone,
        recipientName: req.transferRecipient.name,
        senderPhone: req.authenticatedUser.phone,
        senderName: req.authenticatedUser.name,
        createdAt: new Date().toISOString(),
    };
    const fileMessage = createMessage({
        senderPhone: req.authenticatedUser.phone,
        receiverPhone: req.transferRecipient.phone,
        fileUrl: `/api/transfers/${transfer.id}/download`,
    });

    try {
        saveTransfer(transfer);
        const updatedMessages = [...messagesDatabase, fileMessage];
        persistMessages(updatedMessages);
        messagesDatabase = updatedMessages;
    } catch (error) {
        transfers.delete(transfer.id);
        const transferIndex = `${transferIndexPath}.tmp`;
        fs.writeFileSync(transferIndex, JSON.stringify([...transfers.values()]), { mode: 0o600 });
        fs.renameSync(transferIndex, transferIndexPath);
        fs.unlinkSync(req.file.path);
        console.error('Could not save transfer metadata or message:', error.message);
        return res.status(500).json({ success: false, message: 'The file was received, but its message could not be saved.' });
    }

    res.status(201).json({
        success: true,
        message: `File delivered to ${req.transferRecipient.name}'s inbox.`,
        transfer: {
            id: transfer.id,
            fileName: transfer.fileName,
            fileSize: transfer.fileSize,
            recipientName: req.transferRecipient.name,
        },
    });
});

// 📥 8. PRIVATE RECIPIENT INBOX
app.get('/api/transfers/inbox', requireSession, (req, res) => {
    const publicApiUrl = (process.env.PUBLIC_API_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
    const inbox = [...transfers.values()]
        .filter((transfer) => transfer.recipientPhone === req.authenticatedUser.phone)
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
        .map((transfer) => {
            const ticket = signToken({
                phone: req.authenticatedUser.phone,
                transferId: transfer.id,
                expiresAt: Date.now() + DOWNLOAD_TICKET_DURATION_MS,
                purpose: 'download',
            });
            return {
                id: transfer.id,
                fileName: transfer.fileName,
                fileSize: transfer.fileSize,
                senderName: transfer.senderName,
                createdAt: transfer.createdAt,
                downloadUrl: `${publicApiUrl}/api/transfers/${transfer.id}/download?ticket=${ticket}`,
            };
        });
    res.json({ success: true, transfers: inbox });
});

// 🔗 9. SHORT-LIVED PRIVATE DOWNLOAD TICKET
app.get('/api/transfers/:id/download', (req, res) => {
    const transfer = transfers.get(req.params.id);
    if (!transfer) {
        return res.status(404).send('This file is no longer available.');
    }
    const ticket = verifyToken(req.query.ticket);
    if (!ticket || ticket.purpose !== 'download' || ticket.transferId !== transfer.id || (ticket.phone !== transfer.recipientPhone && ticket.phone !== transfer.senderPhone)) {
        return res.status(403).send('This download is unauthorized or has expired. Refresh your inbox and try again.');
    }

    const filePath = path.join(uploadDirectory, transfer.storedName);
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('This file is no longer available.');
    }

    res.download(filePath, transfer.fileName);
});

if (frontendDirectory) {
    app.get('/{*splat}', (req, res, next) => {
        if (req.path.startsWith('/api/')) return next();
        res.sendFile(path.join(frontendDirectory, 'index.html'), (error) => {
            if (error) next(error);
        });
    });
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log('⚡ FastShare Core Business Logic Injected!');
    console.log(`🚀 FastShare app available at http://localhost:${PORT}`);
});
