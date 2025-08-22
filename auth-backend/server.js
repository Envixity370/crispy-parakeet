require('dotenv').config();

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const app = express();
app.set('trust proxy', 1);
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');

app.use(cors({
	origin: 'https://crispy-parakeet-1.onrender.com',
	credentials: true
}));

app.use(bodyParser.json());

const logDirectory = path.join(__dirname, 'logs');
if (!fs.existsSync(logDirectory)) {
	fs.mkdirSync(logDirectory);
}
app.use(express.static(path.join(__dirname, '../public')));
const accessLogStream = fs.createWriteStream(path.join(logDirectory, 'access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: accessLogStream }));
app.use(morgan('dev'));

function logError(error, req) {
	const errorLogStream = fs.createWriteStream(path.join(logDirectory, 'error.log'), { flags: 'a' });
	const logEntry = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - ${error.stack || error}\n`;
	errorLogStream.write(logEntry);
	errorLogStream.end();
}

app.use(session({
	secret: process.env.SESSION_SECRET || 'your_secret_key',
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: process.env.NODE_ENV === 'production',
		sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
		httpOnly: true
	},
	store: MongoStore.create({
		mongoUrl: process.env.MONGO_URL || 'mongodb://localhost:27017/sessiondb',
		ttl: 14 * 24 * 60 * 60
	})
}));

const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 10,
	message: { message: 'Too many login attempts, please try again later.' }
});

const mongoose = require('mongoose');
mongoose.connect(process.env.MONGO_URL || 'mongodb://localhost:27017/sessiondb', {
	useNewUrlParser: true,
	useUnifiedTopology: true
});

const analyticsSchema = new mongoose.Schema({
	type: String,
	username: String,
	timestamp: { type: Date, default: Date.now },
	details: mongoose.Schema.Types.Mixed
});
const Analytics = mongoose.model('Analytics', analyticsSchema);
const os = require('os');

const userSchema = new mongoose.Schema({
	username: { type: String, required: true, unique: true },
	password: { type: String, required: true },
	avatar: { type: String },
	color: { type: String },
	discordUsername: { type: String },
	discordAvatar: { type: String }
});

app.get('/profile', async (req, res) => {
	if (!req.session.user) return res.status(401).json({ message: 'Not authenticated' });
	try {
	const user = await User.findOne({ username: req.session.user });
	if (!user) return res.status(404).json({ message: 'User not found' });
	res.json({
		username: user.username,
		avatar: user.avatar,
		color: user.color,
		discordUsername: user.discordUsername,
		discordAvatar: user.discordAvatar
	});
	} catch {
	res.status(500).json({ message: 'Failed to fetch profile' });
	}
});

app.post('/profile', async (req, res) => {
	if (!req.session.user) return res.status(401).json({ message: 'Not authenticated' });
	const { username, avatar, color, discordUsername, discordAvatar } = req.body;
	try {
	const user = await User.findOne({ username: req.session.user });
	if (!user) return res.status(404).json({ message: 'User not found' });
	if (avatar !== undefined) user.avatar = avatar;
	if (color !== undefined) user.color = color;
	if (discordUsername !== undefined) user.discordUsername = discordUsername;
	if (discordAvatar !== undefined) user.discordAvatar = discordAvatar;
		await user.save();
		res.json({ message: 'Profile updated!' });
	} catch {
		res.status(500).json({ message: 'Failed to update profile' });
	}
});

const User = mongoose.model('User', userSchema);

const initialUsers = [
	{ username: 'Meer', password: 'Discord' },
	{ username: 'Laura', password: 'Lennon' },
	{ username: 'Lua', password: 'Aim' },
	{ username: '0xFe', password: 'Rat' }
];

async function migrateUsers() {
	for (const u of initialUsers) {
		const exists = await User.findOne({ username: u.username });
		if (!exists) {
			const passwordHash = await bcrypt.hash(u.password, 10);
			await User.create({ username: u.username, password: passwordHash });
			console.log(`Migrated user: ${u.username}`);
		}
	}
	migrateUsers().catch(console.error);
}
migrateUsers().catch(console.error);

app.post('/login', loginLimiter, async (req, res) => {
	const { username, password } = req.body;
	try {
		const user = await User.findOne({ username });
		if (!user) {
			console.log(`Failed login for username: ${username}`);
			fs.appendFileSync(path.join(logDirectory, 'access.log'), `[${new Date().toISOString()}] Failed login for username: ${username}\n`);
			return res.status(400).json({ message: 'Invalid username or password' });
		}
		const validPassword = await bcrypt.compare(password, user.password);
		if (!validPassword) {
			console.log(`Failed login for username: ${username}`);
			fs.appendFileSync(path.join(logDirectory, 'access.log'), `[${new Date().toISOString()}] Failed login for username: ${username}\n`);
			return res.status(400).json({ message: 'Invalid username or password' });
		}
		req.session.user = username;
		console.log(`Successful login for username: ${username}`);
		fs.appendFileSync(path.join(logDirectory, 'access.log'), `[${new Date().toISOString()}] Successful login for username: ${username}\n`);
		await Analytics.create({ type: 'login', username });
		res.status(200).json({ message: 'Login successful' });
	} catch (err) {
		logError(err, req);
		console.error('Login error:', err);
		res.status(500).json({ message: 'Internal server error' });
	}
});

app.get('/auth-status', (req, res) => {
	if (req.session.user) {
		res.json({ authenticated: true, user: req.session.user });
	} else {
		res.json({ authenticated: false });
	}
});

app.post('/logout', (req, res) => {
	const username = req.session.user;
	req.session.destroy(err => {
		if (err) {
			logError(err, req);
			fs.appendFileSync(path.join(logDirectory, 'access.log'), `[${new Date().toISOString()}] Logout failed for user: ${username}\n`);
			return res.status(500).json({ message: 'Logout failed' });
		}
		fs.appendFileSync(path.join(logDirectory, 'access.log'), `[${new Date().toISOString()}] User logged out: ${username}\n`);
		res.json({ message: 'Logged out successfully' });
	});
});

app.get('/analytics', async (req, res) => {
	try {
			const webhooks = await Analytics.countDocuments({ type: 'webhook' });
			// Backend metrics
			const uptime = os.uptime();
			const totalMem = os.totalmem();
			const freeMem = os.freemem();
			const usedMem = totalMem - freeMem;
			const memUsage = ((usedMem / totalMem) * 100).toFixed(2);
			const cpus = os.cpus();
			// Calculate average CPU usage (last minute)
			let cpuUsage = 0;
			if (cpus.length > 0) {
				const cpu = cpus[0];
				const total = Object.values(cpu.times).reduce((a, b) => a + b, 0);
				cpuUsage = ((1 - cpu.times.idle / total) * 100).toFixed(2);
			}
			const loadAvg = os.loadavg();
			// Network stats
			const net = os.networkInterfaces();
			let netStats = [];
			Object.keys(net).forEach(iface => {
				net[iface].forEach(addr => {
					if (!addr.internal && addr.family === 'IPv4') {
						netStats.push({ iface, address: addr.address });
					}
				});
			});
			res.json({
					totalWebhooks: webhooks,
					uptime,
					memUsage: memUsage + '%',
					usedMem,
					totalMem,
					cpuUsage: cpuUsage + '%',
					loadAvg,
					netStats
			});
	} catch (err) {
		res.status(500).json({ message: 'Failed to fetch analytics' });
	}
});



app.use((err, req, res, next) => {
	logError(err, req);
	console.error('Unhandled error:', err);
	res.status(500).json({ message: 'Internal server error' });
});
app.post('/logout', (req, res) => {
	const username = req.session.user;
	req.session.destroy(err => {
		if (err) {
			logError(err, req);
			fs.appendFileSync(path.join(logDirectory, 'access.log'), `[${new Date().toISOString()}] Logout failed for user: ${username}\n`);
			return res.status(500).json({ message: 'Logout failed' });
		}
		fs.appendFileSync(path.join(logDirectory, 'access.log'), `[${new Date().toISOString()}] User logged out: ${username}\n`);
		res.json({ message: 'Logged out successfully' });
	});
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Error handling middleware
app.use((err, req, res, next) => {
	logError(err, req);
	console.error('Unhandled error:', err);
	res.status(500).json({ message: 'Internal server error' });
});
