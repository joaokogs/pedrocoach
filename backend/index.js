const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

const DB_PATH = path.join(__dirname, 'account.json');

async function readDB() {
	try {
		const data = await fs.readFile(DB_PATH, 'utf8');
		return JSON.parse(data || '[]');
	} catch (err) {
		if (err.code === 'ENOENT') return [];
		throw err;
	}
}

async function writeDB(users) {
	await fs.writeFile(DB_PATH, JSON.stringify(users, null, 2), 'utf8');
}

const SALT_ROUNDS = 10;

function withoutPassword(user) {
	const { password, ...rest } = user;
	return rest;
}

app.post('/register', async (req, res) => {
	const { name, cpf, email, password } = req.body;
	if (!name || !cpf || !email || !password) {
		return res.status(400).json({ error: 'name, cpf, email and password are required' });
	}

	const users = await readDB();
	if (users.find(u => u.cpf === cpf)) {
		return res.status(409).json({ error: 'CPF already registered' });
	}
	if (users.find(u => u.email === email)) {
		return res.status(409).json({ error: 'Email already registered' });
	}

	const hashed = await bcrypt.hash(password, SALT_ROUNDS);
	const user = { name, cpf, email, password: hashed, createdAt: new Date().toISOString() };
	users.push(user);
	await writeDB(users);

	return res.status(201).json({ message: 'User registered', user: withoutPassword(user) });
});

app.post('/login', async (req, res) => {
	const { cpf, email, password } = req.body;
	if ((!cpf && !email) || !password) {
		return res.status(400).json({ error: 'Provide cpf or email and password' });
	}
	const users = await readDB();
	const user = users.find(u => (cpf && u.cpf === cpf) || (email && u.email === email));
	if (!user) return res.status(401).json({ error: 'Invalid credentials' });

	const match = await bcrypt.compare(password, user.password);
	if (!match) return res.status(401).json({ error: 'Invalid credentials' });

	return res.json({ message: 'Login successful', user: withoutPassword(user) });
});

app.get('/users', async (req, res) => {
	const users = await readDB();
	return res.json(users.map(withoutPassword));
});

app.get('/users/:cpf', async (req, res) => {
	const { cpf } = req.params;
	const users = await readDB();
	const user = users.find(u => u.cpf === cpf);
	if (!user) return res.status(404).json({ error: 'User not found' });
	return res.json(withoutPassword(user));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
