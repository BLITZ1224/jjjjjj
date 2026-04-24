require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v2: cloudinary } = require('cloudinary');

const app = express();
const server = http.createServer(app);

// Proxy settings for Render/Heroku
app.set('trust proxy', 1);

const io = new Server(server, {
    cors: { 
        origin: "*", 
        methods: ["GET", "POST"]
    }
});

// ✅ Helmet Security Config
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            "script-src-attr": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "res.cloudinary.com", "*.cloudinary.com", "via.placeholder.com", "https://api.dicebear.com"],
            "connect-src": ["'self'", "https://res.cloudinary.com", "wss://*", "https://assets.mixkit.co"],
            "media-src": ["'self'", "data:", "blob:", "https://res.cloudinary.com", "*.cloudinary.com", "https://assets.mixkit.co"],
        },
    },
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'your_fallback_secret';
const MONGO_URI = process.env.MONGODB_URI;

// Cloudinary Config
cloudinary.config({ 
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true 
});

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

// MongoDB Connection
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected Successfully!"))
    .catch(err => console.error("❌ DB Error:", err));

// --- Models ---
const userSchema = new mongoose.Schema({
    phone: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    password: { type: String, required: true },
    avatar: { type: String },
    bio: { type: String },
    wallet: { balance: { type: Number, default: 0 } }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
    conversationId: { type: String, index: true },
    senderPhone: { type: String, required: true },
    receiverPhone: { type: String, required: true },
    text: { type: String, required: true },
    type: { type: String, enum: ['text', 'audio'], default: 'text' },
    isSeen: { type: Boolean, default: false }
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// Utility: Conversation ID generator
function getConversationId(a, b) { return [a, b].sort().join(':'); }

// Cloudinary Upload Logic
async function uploadBase64ToCloudinary(dataUrl, folder) {
    const result = await cloudinary.uploader.upload(dataUrl, { folder, resource_type: 'auto' });
    return result.secure_url;
}

// --- Auth Middleware ---
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) { res.status(401).json({ error: 'Invalid token' }); }
}

// --- API Routes ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { phone, password, name } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.findOneAndUpdate({ phone }, { name, password: hashedPassword }, { upsert: true });
        res.status(201).json({ success: true });
    } catch (e) { res.status(500).json({ error: "Register failed" }); }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { phone, password } = req.body;
        const user = await User.findOne({ phone });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: "Invalid credentials" });
        }
        const token = jwt.sign({ id: user._id, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, user: { name: user.name, phone: user.phone } });
    } catch (e) { res.status(500).json({ error: "Login failed" }); }
});

app.get('/api/user/:phone', requireAuth, async (req, res) => {
    try {
        const user = await User.findOne({ phone: req.params.phone }).select('-password');
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(user);
    } catch (e) { res.status(500).json({ error: "Server error" }); }
});

app.get('/api/messages/:myPhone/:peerPhone', requireAuth, async (req, res) => {
    try {
        const cid = getConversationId(req.params.myPhone, req.params.peerPhone);
        const msgs = await Message.find({ conversationId: cid }).sort({ createdAt: 1 }).limit(100);
        res.json(msgs);
    } catch (e) { res.status(500).json({ error: "Load failed" }); }
});

// --- HTML Routing ---
app.get(['/dashboard', '/messages', '/settings', '/edit-profile', '/call'], (req, res) => {
    const page = req.path.split('/')[1];
    res.sendFile(path.join(__dirname, 'public', `${page}.html`));
});

app.use((req, res, next) => {
    if (req.url.startsWith('/api') || req.url.includes('.')) return next();
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Socket.io Middleware ---
io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Auth error'));
    try {
        socket.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) { next(new Error('Auth error')); }
});

// --- Socket.io Connection Logic ---
io.on('connection', (socket) => {
    const myPhone = socket.user.phone;
    socket.join(myPhone);
    console.log(`🚀 User Connected: ${myPhone}`);

    // ၁။ စာပို့ခြင်း (Real-time Messaging)
    socket.on('send-message', async (data) => {
        try {
            const { receiver, text, type = 'text' } = data;
            let finalContent = text;

            if (type === 'audio') {
                finalContent = await uploadBase64ToCloudinary(text, 'mylovechat/voice');
            }

            const msg = await Message.create({
                conversationId: getConversationId(myPhone, receiver),
                senderPhone: myPhone,
                receiverPhone: receiver,
                text: finalContent,
                type
            });

            // ပို့သူရော လက်ခံသူဆီပါ update ပို့ပေးမယ်
            io.to(receiver).to(myPhone).emit('new-message', msg);
        } catch (e) {
            console.error("Msg Error:", e);
        }
    });

    // ၂။ Typing Status
    socket.on('typing', (data) => {
        socket.to(data.receiver).emit('is_typing', { sender: myPhone });
    });

    // ၃။ Mark Seen Logic
    socket.on('mark_seen', async (data) => {
        try {
            const cid = getConversationId(myPhone, data.sender);
            await Message.updateMany(
                { conversationId: cid, receiverPhone: myPhone, isSeen: false }, 
                { isSeen: true }
            );
            socket.to(data.sender).emit('messages_read', { by: myPhone });
        } catch (e) { console.error("Seen Error:", e); }
    });

    // ၄။ Call Signaling
    socket.on('call-user', (data) => {
        io.to(data.userToCall).emit('incoming-call', { 
            signal: data.signalData, 
            from: myPhone, 
            type: data.type 
        });
    });

    socket.on('answer-call', (data) => {
        io.to(data.to).emit('call-accepted', data.signal);
    });

    socket.on('end-call', (data) => {
        io.to(data.to).emit('call-ended');
    });

    socket.on('disconnect', () => {
        console.log(`🔥 User Offline: ${myPhone}`);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
