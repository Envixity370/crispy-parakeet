const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const app = express();
app.use(cors());
app.use(bodyParser.json());

app.use(session({
	secret: 'your_secret_key',
	resave: false,
	saveUninitialized: false,
	cookie: { secure: false }
}));


const users = [
	{ username: 'Meer', password: require('bcrypt').hashSync('Discord', 10) },
	{ username: 'Laura', password: require('bcrypt').hashSync('Lennon', 10) }
];


app.post('/login', async (req, res) => {
	const { username, password } = req.body;

	const user = users.find(u => u.username === username);
	if (!user) {
		return res.status(400).json({ message: 'Invalid username or password' });
	}

	const validPassword = await bcrypt.compare(password, user.password);
	if (!validPassword) {
		return res.status(400).json({ message: 'Invalid username or password' });
	}

	res.status(200).json({ message: 'Login successful' });
		req.session.user = username;
});


app.get('/auth-status', (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, user: req.session.user });
  } else {
    res.json({ authenticated: false });
  }
});


app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ message: 'Logout failed' });
    }
    res.json({ message: 'Logged out successfully' });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
