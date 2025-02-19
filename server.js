const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");
const { db } = require("./firebase"); // Importamos Firestore
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY || "supersecretkey";

app.use(cors({ origin: "http://localhost:3000", credentials: true }));app.use(bodyParser.json());


app.post("/api/register", async (req, res) => {
  try {
    const { email, username, password, role } = req.body;

    if (!email || !username || !password || !role) {
      return res.status(400).json({ statusCode: 400, message: "Todos los campos son obligatorios" });
    }

    const userRef = db.collection("users").where("email", "==", email);
    const snapshot = await userRef.get();
    if (!snapshot.empty) {
      return res.status(400).json({ statusCode: 400, message: "El usuario ya está registrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      email,
      username,
      password: hashedPassword,
      role,
      "date-register": new Date(),
      "last-login": null
    };
    await db.collection("users").add(newUser);

    res.status(201).json({ statusCode: 201, message: "Usuario registrado exitosamente" });
  } catch (error) {
    res.status(500).json({ statusCode: 500, message: "Error en el registro", error: error.message });
  }
});


app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ statusCode: 400, message: "Se necesitan credenciales" });
    }

    // Buscar usuario en Firebase
    const userRef = db.collection("users").where("email", "==", email);
    const snapshot = await userRef.get();
    
    if (snapshot.empty) {
      return res.status(401).json({ statusCode: 401, message: "Credenciales inválidas" });
    }

    let userData;
    let userId;
    snapshot.forEach(doc => {
      userData = doc.data();
      userId = doc.id;
    });

    const isMatch = await bcrypt.compare(password, userData.password);
    if (!isMatch) {
      return res.status(401).json({ statusCode: 401, message: "Credenciales inválidas" });
    }

    const token = jwt.sign({ email: userData.email, role: userData.role }, SECRET_KEY, { expiresIn: "1m" });

    await db.collection("users").doc(userId).update({ "last-login": new Date() });

    res.json({
      statusCode: 200,
      intDataMessage: [{ credentials: token }]
    });
  } catch (error) {
    res.status(500).json({ statusCode: 500, message: "Error en el login", error: error.message });
  }
});


const verifyToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
  
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(403).json({ statusCode: 403, message: "Token es requerido" });
    }
  
    const token = authHeader.split(" ")[1]; 
  
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.status(401).json({ statusCode: 401, message: "Token inválido o expirado" });
      }
      req.user = decoded;
      next();
    });
  };

app.get("/api/protected", verifyToken, (req, res) => {
  res.json({ statusCode: 200, message: "Acceso concedido", user: req.user });
});


app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});