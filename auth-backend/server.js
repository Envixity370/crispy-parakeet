require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const app = express();
app.set('trust proxy', 1); // For express-rate-limit behind proxy (Render)
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');

// CORS: allow only your frontend domain (replace with your actual domain)
app.use(cors({
	origin: 'https://crispy-parakeet-1.onrender.com',
	credentials: true
}));

app.use(bodyParser.json());

// Setup log directory and streams
const logDirectory = path.join(__dirname, 'logs');
if (!fs.existsSync(logDirectory)) {
	fs.mkdirSync(logDirectory);
}
const accessLogStream = fs.createWriteStream(path.join(logDirectory, 'access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: accessLogStream }));
app.use(morgan('dev'));

// Custom error logger
function logError(error, req) {
	const errorLogStream = fs.createWriteStream(path.join(logDirectory, 'error.log'), { flags: 'a' });
	const logEntry = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - ${error.stack || error}\n`;
	errorLogStream.write(logEntry);
	errorLogStream.end();
}

// Session secret from environment variable
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
		ttl: 14 * 24 * 60 * 60 // 14 days
	})
}));

// Rate limiting for login endpoint
const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 10, // limit each IP to 10 requests per windowMs
	message: { message: 'Too many login attempts, please try again later.' }
});

// User model for MongoDB
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGO_URL || 'mongodb://localhost:27017/sessiondb', {
	useNewUrlParser: true,
	useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
	username: { type: String, required: true, unique: true },
	password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Migrate hardcoded users to MongoDB if not present
const initialUsers = [
	{ username: 'Meer', password: 'Discord' },
	{ username: 'Laura', password: 'Lennon' },
	{ username: 'Lua', password: 'Aim' }
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Error handling middleware
app.use((err, req, res, next) => {
	logError(err, req);
	console.error('Unhandled error:', err);
	res.status(500).json({ message: 'Internal server error' });
});
