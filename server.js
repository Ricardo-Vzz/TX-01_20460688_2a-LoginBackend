//en servidor backend se corre usando: node server.js o tambien nodemon server.js
//en servidor frontend se corre usando: tambien npm run dev

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

const users = [
  {
    username: crypto.createHash("sha1").update("admin").digest("hex"),
    password: hashPasswordSync("password123"),
  },
]

const sesion = {};
const csrfTokens = new Set()

const secureCookieOptions = ()=>({
    httpOnly: true,
    secure: false,
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

function generateCSRFToken() {
  const token = crypto.randomBytes(32).toString("hex");
  csrfTokens.add(token);
  // Limpiar tokens viejos después de 1 hora
  setTimeout(() => csrfTokens.delete(token), 3600000);
  return token;
}

app.get('/', (req, res) => {
    res.send('Hola roño!');
});

app.get('/csrf-token', (req, res) => {
  const csrfToken = generateCSRFToken();
  res.json({ csrfToken });
});
app.post("/login", (req, res) => {
  const { username, password, csrfToken } = req.body;
  
    if (!csrfToken || !csrfTokens.has(csrfToken)) {
        return res.status(403).json({ error: "Invalid CSRF token" });
    }
    csrfTokens.delete(csrfToken);
    
    if (!username || !password) {
        res.writeHead(400)
        res.end(JSON.stringify({ error: "Usuario y contraseña son requeridos" }))
        return
    }

    const hashedUsername = hashUsername(username)
    const user = users.find((u) => u.username === hashedUsername)

    if (!user) {
        res.writeHead(401)
        res.end(JSON.stringify({ error: "Datos incorrectos" }))
        return
    }

    if (!verifyPassword(password, user.password)) {
        res.writeHead(401)
        res.end(JSON.stringify({ error: "Datos incorrectos" }))
        return
    }

    const existingSession = Object.values(sesion).find(session => session.username === username);
    if (existingSession) {
        return res.status(400).json({ error: "Ya tienes una sesión activa" });
    }

    const sesionID = crypto.randomBytes(16).toString("base64url");
    sesion[sesionID] = { username };
    res.cookie("sesionID", sesionID, secureCookieOptions());
    res.status(200).json({ message: "Login successful" });
});

app.post("/register", (req, res) => {
    const { username, password, confirmPassword, csrfToken } = req.body
    // Verificar token CSRF
      if (!verifyCSRFToken(csrfToken)) {
        res.writeHead(403)
        res.end(JSON.stringify({ error: "Token CSRF inválido" }))
        return
      }

      if (!username || !password || !confirmPassword) {
        res.writeHead(400)
        res.end(JSON.stringify({ error: "Todos los campos son requeridos" }))
        return
      }

      if (password !== confirmPassword) {
        res.writeHead(400)
        res.end(JSON.stringify({ error: "Las contraseñas no coinciden" }))
        return
      }

      if (!validatePassword(password)) {
        res.writeHead(400)
        res.end(
          JSON.stringify({
            error:
              "La contraseña debe tener mínimo 8 caracteres, incluyendo mayúsculas, minúsculas, un número y un carácter especial.",
          }),
        )
        return
      }
        // Verificar si el usuario ya existe
      const hashedUsername = hashUsername(username)
      const existingUser = users.find((u) => u.username === hashedUsername)

      if (existingUser) {
        res.writeHead(400)
        res.end(JSON.stringify({ error: "El usuario ya existe" }))
        return
      }

      const hashedPassword = hashPasswordSync(password)
      users.push({
        username: hashedUsername,
        password: hashedPassword,
        createdAt: new Date(),
      })
      res.writeHead(201)
      res.end(JSON.stringify({ message: "Cuenta creada correctamente" }))
});

//ruta de sesión válida
app.get("/dashboard", (req, res) => {
  const sesionID = req.cookies.sesionID;

  if (!sesionID || !sesion[sesionID]) {
    return res.status(401).json({ error: "No autorizado" });
  }

  const { username } = sesion[sesionID];
  res.status(200).json({ username });
});

app.post("/logout", (req, res) => {
  const sesionID = req.cookies.sesionID;
  if (sesionID && sesion[sesionID]) {
    delete sesion[sesionID];
    res.clearCookie("sesionID", secureCookieOptions());
  }
  res.status(200).json({ message: "Sesión cerrada" });
});

//FUNCIONES DE HASHING
function hashPasswordSync(password) {
  const salt = crypto.randomBytes(16).toString("hex")
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex")
  return `${salt}:${hash}`
}
function verifyPassword(password, storedPassword) {
  const [salt, hash] = storedPassword.split(":")
  const verifyHash = crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex")
  return hash === verifyHash
}
function hashUsername(username) {
  return crypto.createHash("sha1").update(username.toLowerCase()).digest("hex")
}

//validar contraseña
function validatePassword(password) {
  if (password.length < 8) return false
  if (!/[a-z]/.test(password)) return false
  if (!/[A-Z]/.test(password)) return false
  if (!/[0-9]/.test(password)) return false
  if (!/[^A-Za-z0-9]/.test(password)) return false
  return true
}