//en servidor backend se corre usando: node server.js o tambien nodemon server.js
//en servidor frontend se corre usando: npm start o tambien npm run dev

const express = require('express');
const cookieParser = require('cookie-parser');
const csrf = require('csrf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const cors = require('cors');

dotenv.config();
//El puerto de el backend es el 3001
const port = process.env.PORT || 3001;
const SECRET_KEY = process.env.SECRET_KEY || 'secret';

const users=[
    {username:"h", password:"a"}
];

const sesion = {};

const secureCookieOptions = ()=>({
    httpOnly: true,
    secure: true,
    sameSite: "strict",
});

const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({extended: true }));
app.use(cors({
    //Este es el puerto del frontend
    origin: "http://localhost:3000",
    credentials: true,
}));

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});

app.get('/', (req, res) => {
    res.send('Hola roño!');
});

app.get('/csrf-token', (req, res) => {
    const csrfToken = new csrf().create(SECRET_KEY);
    res.json({ csrfToken });
});

app.post("/login", (req, res) => {
    const csrfInstance = new csrf();
    const { username, password, csrfToken } = req.body;

    // Verificar el token CSRF
    if (!csrfInstance.verify(SECRET_KEY, csrfToken)) {
        return res.status(403).json({ error: "Invalid CSRF token" });
    }

    // Verificar que el usuario y la contraseña estén presentes
    if (!username || !password) {
        return res.status(400).json({ error: "Usuario y contraseña son requeridos" });
    }

    // Verificar las credenciales del usuario
    const user = users.find(user => user.username === username && user.password === password);
    if (!user) {
        return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    // Verificar sesión activa
    const existingSession = Object.values(sesion).find(session => session.username === username);
    if (existingSession) {
        return res.status(400).json({ error: "Ya tienes una sesión activa" });
    }

    // Crear una sesión y devolver una cookie segura
    const sesionID = crypto.randomBytes(16).toString("base64url");
    sesion[sesionID] = { username };
    res.cookie("sesionID", sesionID, secureCookieOptions());
    res.status(200).json({ message: "Login successful" });
});


//Validacion de la contraseña
function validarPassword(req, res, next) {
    if (password.length < 10) {
        return false;
    }
    if (!/[a-z]/.test(password)) {
        return false;
    }
    if (!/[A-Z]/.test(password)) {
        return false;
    }
    if (!/[0-9]/.test(password)) {
        return false;
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        return false;
    }

    return true;
}

//Hash a la contraseña
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return { salt, hash };
}

//Hash al nombre de usuario
function hashUsername(username) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(username, salt, 1000, 64, 'sha512').toString('hex');
    return { salt, hash };
}

//verificar la contraseña
function verificarPassword(password, hash, salt) {
    const hashVerificado = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash === hashVerificado;
}

//verificar el nombre de usuario
function verificarUsername(username, hash, salt) {
    const hashVerificado = crypto.pbkdf2Sync(username, salt, 1000, 64, 'sha512').toString('hex');
    return hash === hashVerificado;
}

