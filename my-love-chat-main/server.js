require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const helmet = require('helmet');
const { v2: cloudinary } = require('cloudinary');

const app = express();
const server = http.createServer(app);

app.set('trust proxy', 1);

const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// ✅ Helmet Security Config (Media & Socket အတွက်)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            "img-src": ["'self'", "data:", "res.cloudinary.com", "*.cloudinary.com", "via.placeholder.com", "https://api.dicebear.com"],
            "connect-src": ["'self'", "https://res.cloudinary.com", "wss://*", "https://assets.mixkit.co"],
            "media-src": ["'self'", "data:", "blob:", "https://res.cloudinary.com", "https://assets.mixkit.co"],
        },
    },
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'blitz_secret_key';
const MONGO_URI = process.env.MONGODB_URI;

// Cloudinary Config
cloudinary.config({ 
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET 
});

// MongoDB Connection
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ DB Connected!"))
    .catch(err => console.error("❌ DB Error:", err));

// --- Models ---
const userSchema = new mongoose.Schema({
    phone: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    password: { type: String, required: true },
    avatar: { type: String }
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

function getConversationId(a, b) { return [a, b].sort().join(':'); }

// --- Auth Middleware ---
function requireAuth(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) { res.status(401).json({ error: 'Invalid token' }); }
}

// --- API Routes ---
app.post('/api/auth/login', async (req, res) => {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Invalid login" });
    const token = jwt.sign({ phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { name: user.name, phone: user.phone } });
});

// Inbox List API (Chat List ကို ဆွဲထုတ်ပေးမယ့် logic)
app.get('/api/conversations', requireAuth, async (req, res) => {
    try {
        const myPhone = req.user.phone;
        const messages = await Message.find({
            $or: [{ senderPhone: myPhone }, { receiverPhone: myPhone }]
        }).sort({ createdAt: -1 });

        const convos = {};
        for (const msg of messages) {
            const peer = msg.senderPhone === myPhone ? msg.receiverPhone : msg.senderPhone;
            if (!convos[peer]) {
                const user = await User.findOne({ phone: peer }).select('name avatar');
                convos[peer] = {
                    phone: peer,
                    name: user ? user.name : "User",
                    avatar: user ? user.avatar : null,
                    lastMsg: msg.text,
                    time: msg.createdAt,
                    unread: !msg.isSeen && msg.receiverPhone === myPhone
                };
            }
        }
        res.json(Object.values(convos));
    } catch (e) { res.status(500).send(e.message); }
});

// --- Socket.io Logic ---
io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Auth error'));
    try {
        socket.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) { next(new Error('Auth error')); }
});

io.on('connection', (socket) => {
    const myPhone = socket.user.phone;
    socket.join(myPhone);

    // Message ပို့ခြင်း
    socket.on('send-message', async (data) => {
        const { receiver, text, type = 'text' } = data;
        const msg = await Message.create({
            conversationId: getConversationId(myPhone, receiver),
            senderPhone: myPhone, receiverPhone: receiver, text, type
        });
        io.to(receiver).to(myPhone).emit('new-message', msg);
    });

    socket.on('typing', (data) => socket.to(data.receiver).emit('is_typing', { sender: myPhone }));

    socket.on('disconnect', () => console.log("Offline:", myPhone));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Server running on ${PORT}`));
