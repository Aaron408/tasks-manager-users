const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");

require("dotenv").config();

const serviceAccount = {
  type: process.env.TYPE,
  project_id: process.env.PROJECT_ID,
  private_key_id: process.env.PRIVATE_KEY_ID,
  private_key: process.env.PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.CLIENT_EMAIL,
  client_id: process.env.CLIENT_ID,
  auth_uri: process.env.AUTH_URI,
  token_uri: process.env.TOKEN_URI,
  auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_CERT_URL,
  client_x509_cert_url: process.env.CLIENT_CERT_URL,
  universe_domain: process.env.UNIVERSE_DOMAIN,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(express.json());

const verifyToken = (allowedRoles) => async (req, res, next) => {
  console.log("Iniciando verificación de token");
  const token = req.headers["authorization"]?.split(" ")[1];
  console.log("Headers", req.headers);

  if (!token) {
    console.log("Token no proporcionado");
    return res
      .status(401)
      .json({ message: "Acceso denegado. Token no proporcionado." });
  }

  console.log("Token recibido:", token);

  try {
    const db = admin.firestore();
    const tokensRef = db.collection("tokensVerification");
    const tokenSnapshot = await tokensRef.where("token", "==", token).get();

    if (tokenSnapshot.empty) {
      console.log("Token inválido o no encontrado");
      return res
        .status(401)
        .json({ message: "Token inválido o no encontrado." });
    }

    const tokenData = tokenSnapshot.docs[0].data();
    console.log("Datos del token:", tokenData);

    //Verificar si el token ha expirado usando Timestamp de Firestore
    const now = admin.firestore.Timestamp.now();

    if (tokenData.expiresAt instanceof admin.firestore.Timestamp) {
      if (tokenData.expiresAt.toMillis() < now.toMillis()) {
        console.log("Token expirado");
        return res.status(401).json({ message: "Token ha expirado." });
      }
    } else {
      try {
        const expiresAtDate = new Date(tokenData.expiresAt);
        if (isNaN(expiresAtDate.getTime())) {
          console.log("Formato de fecha inválido:", tokenData.expiresAt);
          return res
            .status(401)
            .json({ message: "Error en formato de fecha de expiración." });
        }

        if (expiresAtDate < new Date()) {
          console.log("Token expirado");
          return res.status(401).json({ message: "Token ha expirado." });
        }
      } catch (error) {
        console.error("Error al procesar la fecha de expiración:", error);
        return res
          .status(401)
          .json({ message: "Error al verificar la expiración del token." });
      }
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (decoded.role && !allowedRoles.includes(decoded.role)) {
        console.log("Permisos insuficientes desde JWT. Rol:", decoded.role);
        return res.status(403).json({
          message: "Acceso denegado. Permisos insuficientes.",
        });
      }

      if (decoded.role) {
        req.user = { id: decoded.id, role: decoded.role, email: decoded.email };
        return next();
      }
    } catch (jwtError) {
      console.log(
        "Error al verificar JWT, continuando con verificación en DB:",
        jwtError.message
      );
    }

    const usersRef = db.collection("users");
    const userSnapshot = await usersRef.doc(tokenData.userId).get();

    if (!userSnapshot.exists) {
      console.log("Usuario no encontrado");
      return res.status(401).json({ message: "Usuario no encontrado." });
    }

    const userData = userSnapshot.data();
    console.log("Datos del usuario:", userData);

    if (!allowedRoles.includes(userData.role)) {
      console.log("Permisos insuficientes. Rol del usuario:", userData.role);
      return res
        .status(403)
        .json({ message: "Acceso denegado. Permisos insuficientes." });
    }

    console.log("Token verificado exitosamente");
    req.user = { id: tokenData.userId, role: userData.role };
    next();
  } catch (error) {
    console.error("Error en la verificación del token:", error);
    res
      .status(500)
      .json({ message: "Error al verificar el token.", error: error.message });
  }
};

app.get("/", (req, res) => {
  res.send("Users service running!");
});

app.post("/register", async (req, res) => {
  const { username, fullName, birthDate, email, password } = req.body;

  try {
    // Verificamos si el usuario ya existe
    const usersRef = db.collection("users");
    const snapshot = await usersRef.where("email", "==", email).get();

    if (!snapshot.empty) {
      return res.status(400).json({ message: "El correo ya está registrado" });
    }

    // Hasheo de la contraseña
    const saltRounds = 10; // Número de rondas de hasheo
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Creamos un nuevo usuario en la base de datos
    const newUser = {
      username,
      fullName,
      birthDate,
      email,
      password: hashedPassword,
      role: "mortal",
    };

    // Mandamos el nuevo usuario para su registro en la colección
    await usersRef.add(newUser);
    return res.status(201).json({ message: "Registro exitoso", user: newUser });
  } catch (error) {
    console.error("Error en el registro:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

app.get("/usersList", verifyToken(["admin", "mortal"]), async (req, res) => {
  try {
    const userIdToExclude = req.user.id; // ID del usuario autenticado

    const usersRef = db.collection("users");
    const usersSnapshot = await usersRef.get();

    if (usersSnapshot.empty) {
      return res.status(404).json({ message: "No se encontraron usuarios" });
    }

    const users = usersSnapshot.docs
      .map((doc) => ({
        id: doc.id,
        ...doc.data(),
      }))
      .filter((user) => user.id !== userIdToExclude);

    return res.status(200).json({ users });
  } catch (error) {
    console.error("Error al obtener usuarios:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

app.patch("/users/:userId/role", verifyToken(["admin"]), async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    // Validate role
    if (!role || !["admin", "mortal"].includes(role)) {
      return res.status(400).json({ message: "Rol inválido" });
    }

    const userRef = db.collection("users").doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    await userRef.update({ role });

    res.status(200).json({ message: "Rol actualizado exitosamente" });
  } catch (error) {
    console.error("Error al actualizar el rol del usuario:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

const PORT = process.env.USERS_SERVICE_PORT || 5004;
app.listen(PORT, () => {
  console.log(`Users service running on http://localhost:${PORT}`);
});
