//en servidor backend se corre usando: node server.js o tambien nodemon server.js
//en servidor frontend se corre usando: tambien npm run dev

const express = require('express');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const crypto = require('crypto');
const cors = require('cors');

dotenv.config();
//El puerto de el backend es el 3001
const port = process.env.PORT || 3001;

const SESSION_DURATION = 1000 * 60 * 60; // 1 hora de sesión

const users = [
  {
    username: crypto.createHash("sha1").update("admin").digest("hex"),
    password: hashPasswordSync("Password123"),
  },
]

const sesion = {};

const secureCookieOptions = ()=>({
    httpOnly: true,
    secure: false,
    sameSite: "lax",
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

app.post("/login", (req, res) => {
  const { username, password } = req.body;

    if (!username || !password) {
        res.status(400).json({ error: "Usuario y contraseña son requeridos" });
        return
    }

    const hashedUsername = hashUsername(username)
    const user = users.find((u) => u.username === hashedUsername)

    if (!user) {
        return res.status(401).json({ error: "Datos incorrectos" });
    }

    if (!verifyPassword(password, user.password)) {
        return res.status(401).json({ error: "Datos incorrectos" });
    }

    const existingSession = Object.values(sesion).find(session => session.username === username);
    if (existingSession) {
        return res.status(400).json({ error: "Ya tienes una sesión activa" });
    }



    const sesionID = crypto.randomBytes(16).toString("base64url");
    const expireAt = Date.now() + SESSION_DURATION;
    sesion[sesionID] = { username, expireAt };
    res.cookie("sesionID", sesionID,{...secureCookieOptions(), maxAge: SESSION_DURATION});
    res.status(200).json({ message: "Login successful" });
});

app.post("/register", (req, res) => {
    const { username, password, confirmPassword, } = req.body

      if (!username || !password || !confirmPassword) {
        return res.status(400).json({ error: "Todos los campos son requeridos" });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({ error: "Las contraseñas no coinciden" });
      }

      if (!validatePassword(password)) {
        return res.status(400).json({error:"La contraseña debe tener mínimo 8 caracteres, incluyendo mayúsculas, minúsculas, un número y un carácter especial."});
      }
        // Verificar si el usuario ya existe
      const hashedUsername = hashUsername(username)
      const existingUser = users.find((u) => u.username === hashedUsername)

      if (existingUser) {
        return res.status(400).json({ error: "El usuario ya existe" });
      }

      const hashedPassword = hashPasswordSync(password)
      users.push({
        username: hashedUsername,
        password: hashedPassword,
        createdAt: new Date(),
      })
      res.status(201).json({ message: "Cuenta creada correctamente" });
});

//ruta de sesión válida
app.get("/dashboard", (req, res) => {
  const sesionID = req.cookies.sesionID;

  if (!sesionID || !sesion[sesionID]) {
    return res.status(401).json({ error: "No autorizado" });
  }

  const sessionData = sesion[sesionID];
  if (Date.now() > sessionData.expiresAt) {
    delete sesion[sesionID];
    res.clearCookie("sesionID", secureCookieOptions());
    return res.status(401).json({ error: "Sesión expirada" });
  }

  // Renovar expiración
  sessionData.expireAt = Date.now() + SESSION_DURATION;
  res.cookie("sesionID", sesionID, { ...secureCookieOptions(), maxAge: SESSION_DURATION });

  res.status(200).json({ username: sessionData.username, message: "Sesión válida" });
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
function validatePassword(password) {//la contraseña debe tener mínimo 8 caracteres, incluyendo mayúsculas, minúsculas, un número y un carácter especial.
  if (password.length < 8) return false
  if (!/[a-z]/.test(password)) return false
  if (!/[A-Z]/.test(password)) return false
  if (!/[0-9]/.test(password)) return false
  if (!/[^A-Za-z0-9]/.test(password)) return false
  return true
}