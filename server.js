// servidor2.js (Servidor sin rate limit)
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const bodyParser = require("body-parser");
const speakeasy = require("speakeasy");
const { db } = require("./firebase");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT2 || 5002;
const SECRET_KEY = process.env.SECRET_KEY || "supersecretkey";

const allowedOrigins = [
  "http://localhost:3000",
  "https://frontendproyectofinal.onrender.com" 
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("No autorizado por CORS"));
    }
  },
  credentials: true
}));
app.use(bodyParser.json()); 

app.use((req, res, next) => {
  const startTime = Date.now();

  res.on("finish", async () => {
    const responseTime = Date.now() - startTime;
    let logLevel = "info";

    if (res.locals?.customLogLevel) {
      logLevel = res.locals.customLogLevel;
    } else {
      const code = res.statusCode;
      if (code >= 500) logLevel = "critical";
      else if (code >= 400) logLevel = "error";
      else if (code >= 300) logLevel = "warning";
      else if (code >= 200 && code < 300) logLevel = "info";
    }
    const logData = {
      logLevel,
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.url,
      path: req.path,
      query: req.query || {},
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get("User-Agent"),
      protocol: req.protocol,
      hostname: req.hostname,
      system: {
        nodeVersion: process.version,
        environment: process.env.NODE_ENV || "development",
        pid: process.pid
      },
      servidor: "Servidor 2"
    };


    try {
      await db.collection("logs2").add(logData);
    } catch (e) {
      console.error("Error al guardar log en logs2:", e.message);
    }
  });

  next();
});

app.get("/api/getInfo", (req, res) => {
  res.json({
    nodeVersion: process.version,
    alumno: "Uriel Isaí Ortiz Pérez",
    grupo: "IDGS11",
    mensaje: "Servidor 2 sin rate limit. Guarda logs en 'logs2'"
  });
});

app.post("/api/register", async (req, res) => {
  try {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ statusCode: 400, message: "Todos los campos son obligatorios" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ statusCode: 400, message: "Correo inválido" });
    }

    const snapshot = await db.collection("users").where("email", "==", email).get();
    if (!snapshot.empty) {
      return res.status(400).json({ statusCode: 400, message: "El usuario ya existe" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const mfaSecret = speakeasy.generateSecret();

    const newUser = {
      email,
      username,
      password: hashedPassword,
      mfaSecret: mfaSecret.base32,
      "date-register": new Date(),
      "last-login": null
    };

    await db.collection("users").add(newUser);

    res.status(201).json({
      statusCode: 201,
      message: "Usuario registrado exitosamente",
      mfaSetup: mfaSecret.otpauth_url
    });
  } catch (error) {
    res.status(500).json({ statusCode: 500, message: "Error en el registro", error: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password, token } = req.body;

    if (!email || !password || !token) {
      return res.status(400).json({ statusCode: 400, message: "Todos los campos son obligatorios" });
    }

    const snapshot = await db.collection("users").where("email", "==", email).get();
    if (snapshot.empty) {
      return res.status(401).json({ statusCode: 401, message: "Credenciales inválidas" });
    }

    let userData, userId;
    snapshot.forEach(doc => {
      userData = doc.data();
      userId = doc.id;
    });

    const isMatch = await bcrypt.compare(password, userData.password);
    if (!isMatch) {
      return res.status(401).json({ statusCode: 401, message: "Credenciales inválidas" });
    }

    const verified = speakeasy.totp.verify({
      secret: userData.mfaSecret,
      encoding: "base32",
      token
    });

    if (!verified) {
      return res.status(401).json({ statusCode: 401, message: "Código MFA inválido" });
    }

    const payload = {
      email: userData.email,
      username: userData.username
    };

    const authToken = jwt.sign(payload, SECRET_KEY, { expiresIn: "10m" });

    await db.collection("users").doc(userId).update({ "last-login": new Date() });

    res.json({ statusCode: 200, message: "Login exitoso", token: authToken });
  } catch (error) {
    res.status(500).json({ statusCode: 500, message: "Error en el login", error: error.message });
  }
});

// Obtener logs del servidor 2
app.get("/api/logs2", async (req, res) => {
  try {
    const snapshot = await db.collection("logs2").get();

    if (snapshot.empty) {
      return res.status(404).json({ message: "No hay logs disponibles" });
    }

    const logs = [];
    snapshot.forEach(doc => logs.push(doc.data()));

    res.json({ logs });
  } catch (error) {
    res.status(500).json({ message: "Error al obtener logs2", error: error.message });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor 2 (sin Rate Limit) corriendo en http://localhost:${PORT}`);
});
