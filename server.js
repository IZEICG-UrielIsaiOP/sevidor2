const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY || 'supersecretkey';

app.use(cors());
app.use(bodyParser.json());

const users = [
    { username: 'admin', password: 'uri123' },
    { username: 'user', password: 'diferentealurir123' }
];

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ statusCode: 400, message: 'Se necesitan credenciales' });
    }

    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).json({ statusCode: 401, message: 'Credenciales Invalidad' });
    }

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1m' });
    
    res.json({
        statusCode: 200,
        intDataMessage: [{ credentials: token }]
    });
});

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ statusCode: 403, message: 'Token es requerido' });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ statusCode: 401, message: 'Token Invalido' });
        }
        req.user = decoded;
        next();
    });
};

app.get('/api/protected', verifyToken, (req, res) => {
    res.json({ statusCode: 200, message: 'usuario del token', user: req.user });
});

app.listen(PORT, () => {
    console.log(`Servidot corriendo en ${PORT}`);
});
