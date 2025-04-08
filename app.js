const express = require('express');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { addDays, addHours, addMinutes, addWeeks } = require("date-fns");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const ternuServiceKey = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

// Inicializar Firebase Admin
try {
    admin.initializeApp({
        credential: admin.credential.cert(ternuServiceKey),
        projectId: 'ternurines',
    });
    console.log('Firebase Admin SDK inicializado correctamente');
} catch (error) {
    console.error('Error al inicializar Firebase Admin SDK:', error.message);
    process.exit(1);
}

const db = admin.firestore();
const auth = admin.auth();
const app = express();

// Create a map to store SSE clients
const sseClients = new Map();

// Middleware
app.use(express.json());
app.use(cors({
  origin: ['https://ternurines-front.onrender.com', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// SSE endpoint for real-time activity updates
app.get('/events', (req, res) => {
  const userId = req.query.userId;
  
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }

  // Set headers for SSE
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  // Send initial connection message
  res.write(`data: ${JSON.stringify({ type: 'connection', message: 'Connected to activity stream' })}\n\n`);
  
  // Store the client connection
  if (!sseClients.has(userId)) {
    sseClients.set(userId, []);
  }
  sseClients.get(userId).push(res);
  
  // Handle client disconnect
  req.on('close', () => {
    const clients = sseClients.get(userId) || [];
    const index = clients.indexOf(res);
    if (index !== -1) {
      clients.splice(index, 1);
      if (clients.length === 0) {
        sseClients.delete(userId);
      }
    }
  });
});

// Function to send activity to a specific user
const sendActivityToUser = (userId, activity) => {
  const clients = sseClients.get(userId) || [];
  const activityData = JSON.stringify(activity);
  
  clients.forEach(client => {
    client.write(`data: ${activityData}\n\n`);
  });
};

// Log user activity
const logUserActivity = async (userId, activityType, details = {}) => {
  try {
    // Store activity in Firestore
    const activityRef = await db.collection('userActivities').add({
      userId,
      type: activityType,
      details,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Create activity object
    const activity = {
      id: activityRef.id,
      type: activityType,
      ...details,
      timestamp: new Date().toISOString()
    };
    
    // Send to connected clients
    sendActivityToUser(userId, activity);
    
    return activity;
  } catch (error) {
    console.error('Error logging activity:', error);
    return null;
  }
};


// Registro de usuario
app.post('/register', async (req, res) => {
    const { email, username, password } = req.body; // Solo recibir los datos necesarios

    if (!email || !username || !password) {
        return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    // Credenciales para enviar correos (preconfiguradas en el servidor)
    const senderEmail = 'infocuchiternuras@gmail.com'; // Cambia por el correo configurado
    const senderPassword = 'icik ihoq yrhw krho'; // Cambia por la contraseña de la cuenta configurada

    try {
        const userRecord = await auth.createUser({
            email,
            password,
            displayName: username
        });

        // Generar un código aleatorio para el usuario
        const verificationCode = Math.floor(100000 + Math.random() * 900000); // Código de 6 dígitos

        // Encriptar la contraseña antes de guardarla en Firestore
        const hashedPassword = await bcrypt.hash(password, 10);

        // Definir rol automáticamente (admin, master, usuario normal)
        let rol = 2; // Usuario normal
        const adminEmails = ["2022371122@uteq.edu.mx", "otroadmin@empresa.com"];
        const masterEmails = ["master@example.com", "otromaster@empresa.com"];
        if (adminEmails.includes(email)) {
            rol = 1; // Asignar rol de administrador si el correo está en la lista
        } else if (masterEmails.includes(email)) {
            rol = 3; // Asignar rol de master si el correo está en la lista
        }

        // Guardar usuario en Firestore
        await db.collection('users').doc(userRecord.uid).set({
            uid: userRecord.uid,
            email,
            username,
            password: hashedPassword,
            rol,
            verificationCode,  // Guardar el código de verificación
            last_login: admin.firestore.FieldValue.serverTimestamp()
        });

        // Configuración del transporte de correo con credenciales fijas (senderEmail, senderPassword)
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: senderEmail, // Correo preconfigurado para enviar el mensaje
                pass: senderPassword, // Contraseña preconfigurada
            }
        });

        const mailOptions = {
            from: senderEmail, // Correo que envía el mensaje
            to: email, // El correo del usuario registrado
            subject: 'Confirma tu identidad con este código de verificación',
            html: `
                <div style="font-family: Arial, sans-serif; color: #333; padding: 20px;">
                    <h2 style="color: #7D1C4A;">¡Hola!</h2>
                    <p>Gracias por unirte a la familia de <strong>Cuchi Ternuras</strong>. Para asegurarnos de que todo esté en orden, por favor usa el siguiente código de verificación para confirmar tu cuenta:</p>
                    <div style="font-size: 20px; font-weight: bold; color: #7D1C4A; padding: 10px; background: #f8f8f8; border-radius: 5px; text-align: center;">
                        ${verificationCode}
                    </div>
                    <p>Este código es válido por <strong>10 minutos</strong>. Si no solicitaste este código, por favor ignóralo.</p>
                    <p>¡Estamos muy emocionados de que formes parte de nuestra comunidad llena de ternura! 🐣💖</p>
                    <p><strong>Cuchi Ternuras</strong></p>
                </div>
            `
        };
        
        // Enviar el correo
        await transporter.sendMail(mailOptions);

        res.status(201).json({
            message: 'Usuario registrado exitosamente. Se ha enviado un correo de verificación',
            userId: userRecord.uid,
            verificationCode // Enviar el código de verificación también en la respuesta
        });

    } catch (error) {
        console.error('Error en la creación del usuario:', error);
        res.status(500).json({ error: error.message });
    }
});

// Generar Token JWT con datos del usuario
// Update the generateToken function to ensure role is included
const generateToken = (user) => {
  return jwt.sign(
      {
          uid: user.uid,
          username: user.username,
          email: user.email,
          rol: user.rol,  // Make sure role is included in the token
      },
      'secretKey',
      { expiresIn: '1h' }  // Increased token expiration time
  );
};

// Update the login endpoint to properly return the role
// Modify login endpoint to log activity
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
  }

  try {
      const userQuery = await db.collection('users').where('username', '==', username.trim()).get();

      if (userQuery.empty) {
          return res.status(400).json({ error: 'Usuario no encontrado' });
      }

      const userData = userQuery.docs[0].data();
      const userId = userQuery.docs[0].id;

      // Verificación de la contraseña con bcrypt
      const validPassword = await bcrypt.compare(password, userData.password);
      if (!validPassword) {
          return res.status(400).json({ error: 'Contraseña incorrecta' });
      }

      // Generar el token con la información completa del usuario
      const token = generateToken({
          uid: userId,
          username: userData.username,
          email: userData.email,
          rol: userData.rol,
      });

      // Log login activity
      logUserActivity(userId, 'login', {
        message: `Usuario ${userData.username} inició sesión`,
      });

      // Rest of the login code remains the same
      console.log('✅ Usuario ha iniciado sesión:', {
          uid: userId,
          username: userData.username,
          email: userData.email,
          rol: userData.rol,
          token: token,
      });

      res.json({
          message: 'Login exitoso',
          token,
          userId,
          user: {
              uid: userId,
              username: userData.username,
              email: userData.email,
              rol: userData.rol,
              password: userData.password,
          }
      });

  } catch (error) {
      console.error('Error en el login:', error);
      res.status(500).json({ error: error.message });
  }
});


// Middleware para verificar token JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado.' });
  }

  try {
    const verified = jwt.verify(token, 'secretKey');
    req.user = verified;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
};



app.post('/verify-reset-code', async (req, res) => {
    const { email, code } = req.body;
  
    if (!email || !code) {
      return res.status(400).json({ error: "Correo electrónico y código son requeridos." });
    }
  
    try {
      // Buscar el usuario en Firestore
      const userSnapshot = await db.collection('users').where('email', '==', email).limit(1).get();
      if (userSnapshot.empty) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }
  
      const userDoc = userSnapshot.docs[0];
      const userData = userDoc.data();
  
      // Verificar si el código coincide
      if (userData.verificationCode.toString() !== code) {
        return res.status(400).json({ error: 'Código incorrecto o expirado.' });
      }
  
      // Si el código es correcto, puedes actualizar el estado del usuario a "verificado"
      await db.collection('users').doc(userDoc.id).update({ verified: true });
  
      res.status(200).json({ message: 'Correo verificado correctamente.' });
    } catch (error) {
      console.error("Error al verificar el código:", error);
      res.status(500).json({ error: error.message });
    }
  });
  
// Otras rutas aquí...


// Configuración de correo
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'infocuchiternuras@gmail.com', 
        pass: 'icik ihoq yrhw krho'
    }
});

// 🚀 **1. Ruta para solicitar el restablecimiento de contraseña**
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Se requiere un correo electrónico' });
    }

    try {
        const userQuery = await db.collection('users').where('email', '==', email.trim()).get();
        if (userQuery.empty) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const userDoc = userQuery.docs[0];
        const userId = userDoc.id;

        // Generar token único
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetExpires = Date.now() + 3600000; // Expira en 1 hora

        // Guardar el token en la base de datos
        await db.collection('users').doc(userId).update({ resetToken, resetExpires });

        // Enlace para restablecer contraseña
        const resetLink = `http://localhost:3001/reset-password?token=${resetToken}&email=${email}`;

        // Enviar correo con el enlace
        const mailOptions = {
            from: 'infocuchiternuras@gmail.com',
            to: email,
            subject: 'Restablecimiento de Contraseña',
            html: `
                <p>Hola,</p>
                <p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace para cambiarla:</p>
                <a href="${resetLink}">Restablecer Contraseña</a>
                <p>Este enlace expira en 1 hora.</p>
                <p>Si no solicitaste este cambio, ignora este correo.</p>
            `
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: 'Correo enviado. Revisa tu bandeja de entrada.' });

    } catch (error) {
        console.error('Error en la solicitud de restablecimiento:', error);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// 🚀 **2. Ruta para verificar el token y actualizar la contraseña**
app.post('/reset-password', async (req, res) => {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
        return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    try {
        const userQuery = await db.collection('users').where('email', '==', email.trim()).get();
        if (userQuery.empty) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const userDoc = userQuery.docs[0];
        const userId = userDoc.id;
        const userData = userDoc.data();

        if (!userData.resetToken || userData.resetToken !== token || userData.resetExpires < Date.now()) {
            return res.status(400).json({ error: 'Token inválido o expirado' });
        }

        // Encriptar la nueva contraseña
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Actualizar la contraseña y eliminar el token de restablecimiento
        await db.collection('users').doc(userId).update({
            password: hashedPassword,
            resetToken: null,
            resetExpires: null
        });

        res.json({ message: 'Contraseña restablecida correctamente. Redirigiendo al login...' });

    } catch (error) {
        console.error('Error al restablecer contraseña:', error);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});


app.get("/user", async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader) {
      return res.status(401).json({ error: "No se ha proporcionado el token" });
    }
  
    const token = authHeader.split(" ")[1];
  
    try {
      const decoded = jwt.verify(token, "secretKey");
      const userDoc = await db.collection("users").doc(decoded.uid).get();
  
      if (!userDoc.exists) {
        return res.status(404).json({ error: "Usuario no encontrado" });
      }
  
      const user = userDoc.data();
  
      // Envía la contraseña en texto plano
      res.json({
        username: user.username,
        email: user.email,
        password: user.password, // Contraseña en texto plano
      });
    } catch (error) {
      return res.status(401).json({ error: "Token inválido o expirado" });
    }
  });
          

  // Ruta para actualizar perfil
app.put('/updateProfile', async (req, res) => {
    const { username, email } = req.body;
    const token = req.header("Authorization")?.split(" ")[1]; // Obtener token del header

    if (!token) {
        return res.status(401).json({ error: "Acceso denegado. Token no proporcionado." });
    }

    try {
        // Verificar y decodificar el token
        const decoded = jwt.verify(token, 'secretKey');
        const userId = decoded.uid;

        // Validar datos
        if (!username || !email) {
            return res.status(400).json({ error: "Todos los campos son requeridos." });
        }

        // Buscar usuario en Firestore
        const userRef = db.collection('users').doc(userId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: "Usuario no encontrado." });
        }

        // Actualizar datos en Firestore
        await userRef.update({
            username,
            email
        });

        // También actualizar en Firebase Authentication
        await auth.updateUser(userId, {
            displayName: username,
            email: email
        });

        res.json({ message: "Perfil actualizado con éxito." });

    } catch (error) {
        console.error("Error al actualizar perfil:", error);
        res.status(500).json({ error: "Error al actualizar el perfil." });
    }
});

app.get('/carrito', verifyToken, async (req, res) => {
    try {
      const userId = req.user.uid;
      
      // Buscar el carrito del usuario en Firestore
      const cartRef = admin.firestore().collection('carrito').doc(userId);
      const cartDoc = await cartRef.get();
      
      if (!cartDoc.exists) {
        // Si no existe, devolver un carrito vacío
        return res.json({ items: [] });
      }
      
      // Devolver los items del carrito
      const cartData = cartDoc.data();
      res.json({ items: cartData.items || [] });
      
    } catch (error) {
      console.error('Error al obtener el carrito:', error);
      res.status(500).json({ error: 'Error al obtener el carrito' });
    }
  });
  
  // Agregar producto al carrito
  app.post('/carrito/add', verifyToken, async (req, res) => {
    try {
      const userId = req.user.uid;
      const producto = req.body.producto;
      
      if (!producto || !producto.id || !producto.tipo || !producto.nombre || !producto.precio) {
        return res.status(400).json({ error: 'Datos del producto incompletos' });
      }
      
      // Referencia al carrito del usuario
      const cartRef = admin.firestore().collection('carrito').doc(userId);
      const cartDoc = await cartRef.get();
      
      if (!cartDoc.exists) {
        // Si el carrito no existe, crear uno nuevo con el producto
        await cartRef.set({
          userId,
          items: [{ ...producto, cantidad: 1 }],
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        // Log activity
        logUserActivity(userId, 'cart_add', {
          message: `Producto "${producto.nombre}" añadido al carrito`,
          productId: producto.id,
          productName: producto.nombre,
          productType: producto.tipo
        });
        
        return res.json({ 
          message: 'Producto agregado al carrito',
          items: [{ ...producto, cantidad: 1 }]
        });
      }
      
      // Rest of the cart/add code remains the same
      const cartData = cartDoc.data();
      const items = cartData.items || [];
      
      // Verificar si el producto ya está en el carrito
      const existingItemIndex = items.findIndex(item => 
        item.id === producto.id && item.tipo === producto.tipo
      );
      
      if (existingItemIndex >= 0) {
        // Si ya existe, incrementar la cantidad
        items[existingItemIndex].cantidad += 1;
      } else {
        // Si no existe, agregar como nuevo
        items.push({ ...producto, cantidad: 1 });
        
        // Log activity only for new items
        logUserActivity(userId, 'cart_add', {
          message: `Producto "${producto.nombre}" añadido al carrito`,
          productId: producto.id,
          productName: producto.nombre,
          productType: producto.tipo
        });
      }
      
      // Actualizar el carrito en Firestore
      await cartRef.update({
        items,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      res.json({ 
        message: 'Producto agregado al carrito',
        items
      });
      
    } catch (error) {
      console.error('Error al agregar al carrito:', error);
      res.status(500).json({ error: 'Error al agregar al carrito' });
    }
    });
  
  // Actualizar cantidad de un producto en el carrito
  app.put('/carrito/update', verifyToken, async (req, res) => {
    try {
      const userId = req.user.uid;
      const { productoId, tipo, cantidad } = req.body;
      
      if (!productoId || !tipo || cantidad === undefined) {
        return res.status(400).json({ error: 'Datos incompletos' });
      }
      
      // Referencia al carrito del usuario
      const cartRef = admin.firestore().collection('carrito').doc(userId);
      const cartDoc = await cartRef.get();
      
      if (!cartDoc.exists) {
        return res.status(404).json({ error: 'Carrito no encontrado' });
      }
      
      // Actualizar la cantidad del producto
      const cartData = cartDoc.data();
      let items = cartData.items || [];
      
      // Si la cantidad es 0, eliminar el producto
      if (cantidad <= 0) {
        items = items.filter(item => !(item.id === productoId && item.tipo === tipo));
      } else {
        // Actualizar la cantidad
        const itemIndex = items.findIndex(item => item.id === productoId && item.tipo === tipo);
        
        if (itemIndex === -1) {
          return res.status(404).json({ error: 'Producto no encontrado en el carrito' });
        }
        
        items[itemIndex].cantidad = cantidad;
      }
      
      // Actualizar el carrito en Firestore
      await cartRef.update({
        items,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      res.json({ 
        message: 'Carrito actualizado',
        items
      });
      
    } catch (error) {
      console.error('Error al actualizar el carrito:', error);
      res.status(500).json({ error: 'Error al actualizar el carrito' });
    }
  });
  
  // Eliminar producto del carrito
  app.delete('/carrito/remove', verifyToken, async (req, res) => {
    try {
      const userId = req.user.uid;
      const { productoId, tipo } = req.body;
      
      if (!productoId || !tipo) {
        return res.status(400).json({ error: 'Datos incompletos' });
      }
      
      // Referencia al carrito del usuario
      const cartRef = admin.firestore().collection('carrito').doc(userId);
      const cartDoc = await cartRef.get();
      
      if (!cartDoc.exists) {
        return res.status(404).json({ error: 'Carrito no encontrado' });
      }
      
      // Eliminar el producto del carrito
      const cartData = cartDoc.data();
      const items = cartData.items || [];
      const updatedItems = items.filter(item => !(item.id === productoId && item.tipo === tipo));
      
      // Actualizar el carrito en Firestore
      await cartRef.update({
        items: updatedItems,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      res.json({ 
        message: 'Producto eliminado del carrito',
        items: updatedItems
      });
      
    } catch (error) {
      console.error('Error al eliminar del carrito:', error);
      res.status(500).json({ error: 'Error al eliminar del carrito' });
    }
  });
  
  // Vaciar el carrito
  app.delete('/carrito/clear', verifyToken, async (req, res) => {
    try {
      const userId = req.user.uid;
      
      // Referencia al carrito del usuario
      const cartRef = admin.firestore().collection('carrito').doc(userId);
      
      // Actualizar el carrito con un array vacío
      await cartRef.update({
        items: [],
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      res.json({ 
        message: 'Carrito vaciado',
        items: []
      });
      
    } catch (error) {
      console.error('Error al vaciar el carrito:', error);
      res.status(500).json({ error: 'Error al vaciar el carrito' });
    }
  });
  
  // Procesar compra
  app.post('/checkout', verifyToken, async (req, res) => {
    try {
      const userId = req.user.uid;
      const { direccion, metodoPago } = req.body;
      
      if (!direccion || !metodoPago) {
        return res.status(400).json({ error: 'Datos de envío o pago incompletos' });
      }
      
      // Obtener el carrito del usuario
      const cartRef = admin.firestore().collection('carrito').doc(userId);
      const cartDoc = await cartRef.get();
      
      if (!cartDoc.exists || !cartDoc.data().items || cartDoc.data().items.length === 0) {
        return res.status(400).json({ error: 'El carrito está vacío' });
      }
      
      const cartData = cartDoc.data();
      
      // Calcular el total de la compra
      const items = cartData.items;
      const subtotal = items.reduce((total, item) => total + (item.precio * item.cantidad), 0);
      const impuestos = subtotal * 0.16; // 16% de impuestos
      const envio = 150; // Costo fijo de envío
      const total = subtotal + impuestos + envio;
      
      // Crear la orden en Firestore
      const orderRef = await admin.firestore().collection('ordenes').add({
        userId,
        items,
        subtotal,
        impuestos,
        envio,
        total,
        direccion,
        metodoPago,
        estado: 'pendiente',
        fechaCreacion: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Log purchase activity
      logUserActivity(userId, 'purchase', {
        message: 'Compra realizada exitosamente',
        orderId: orderRef.id,
        total: total.toFixed(2),
        items: items.map(item => ({
          nombre: item.nombre,
          cantidad: item.cantidad,
          precio: item.precio
        }))
      });
        
      // Vaciar el carrito después de la compra
      await cartRef.update({
        items: [],
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Obtener datos del usuario para el correo
      const userDoc = await admin.firestore().collection('users').doc(userId).get();
      const userData = userDoc.data();
      
      // Enviar correo de confirmación
      const mailOptions = {
        from: 'infocuchiternuras@gmail.com',
        to: userData.email,
        subject: 'Confirmación de Compra - Cuchi Ternuras',
        html: `
          <div>
            <h2>¡Gracias por tu compra!</h2>
            <p>Hola ${userData.username},</p>
            <p>Tu pedido ha sido recibido y está siendo procesado. Aquí están los detalles:</p>
            
            <div>
              <h3>Resumen de tu pedido</h3>
              <p><strong>Número de orden:</strong> ${orderRef.id}</p>
              <p><strong>Fecha:</strong> ${new Date().toLocaleDateString()}</p>
              <p><strong>Total:</strong> $${total.toFixed(2)}</p>
            </div>
            
            <h3>Productos:</h3>
            <ul>
              ${items.map(item => `
                <li>
                  <strong>${item.nombre}</strong> x ${item.cantidad} - $${(item.precio * item.cantidad).toFixed(2)}
                </li>
              `).join('')}
            </ul>
            
            <div>
              <p><strong>Subtotal:</strong> $${subtotal.toFixed(2)}</p>
              <p><strong>Impuestos:</strong> $${impuestos.toFixed(2)}</p>
              <p><strong>Envío:</strong> $${envio.toFixed(2)}</p>
              <p><strong>Total:</strong> $${total.toFixed(2)}</p>
            </div>
            
            <div>
              <p>Tu pedido será enviado a la siguiente dirección:</p>
              <p>
                ${direccion.calle} ${direccion.numero}, ${direccion.colonia}<br>
                ${direccion.ciudad}, ${direccion.estado}, CP ${direccion.cp}
              </p>
            </div>
            
            <p>Si tienes alguna pregunta sobre tu pedido, no dudes en contactarnos.</p>
            <p>¡Gracias por elegir Cuchi Ternuras!</p>
          </div>
        `
      };
      
      await transporter.sendMail(mailOptions);
      
      res.json({ 
        message: 'Compra realizada con éxito',
        orderId: orderRef.id,
        total
      });
      
    } catch (error) {
      console.error('Error al procesar la compra:', error);
      res.status(500).json({ error: 'Error al procesar la compra' });
    }
  });
    
// MFA endpoints for your backend

// Generate and send MFA code
app.post('/send-mfa-code', async (req, res) => {
  try {
    const { userId, email } = req.body;
    
    // Generate a random 6-digit code
    const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store the code in Firebase
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
    
    await admin.firestore().collection('mfaCodes').doc(userId).set({
      code: mfaCode,
      email,
      expiresAt: admin.firestore.Timestamp.fromDate(expiresAt)
    });
    
    // Send the code via email using the existing transporter
    const mailOptions = {
      from: 'infocuchiternuras@gmail.com',
      to: email,
      subject: 'Código de verificación - CuchiTernuras',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #9C2780; text-align: center;">Verificación de Inicio de Sesión</h2>
          <p>Hola,</p>
          <p>Tu código de verificación para iniciar sesión en CuchiTernuras es:</p>
          <div style="text-align: center; margin: 20px 0;">
            <div style="font-size: 24px; font-weight: bold; letter-spacing: 5px; padding: 10px; background-color: #f5f5f5; border-radius: 5px; display: inline-block;">${mfaCode}</div>
          </div>
          <p>Este código expirará en 10 minutos.</p>
          <p>Si no has intentado iniciar sesión, por favor ignora este mensaje.</p>
          <p>Saludos,<br>El equipo de CuchiTernuras</p>
        </div>
      `
    };

    // Actually send the email
    await transporter.sendMail(mailOptions);
    
    // For testing, log the code to the console
    console.log(`Código MFA para ${email}: ${mfaCode}`);
    
    res.status(200).json({ success: true, message: 'Código enviado correctamente' });
  } catch (error) {
    console.error('Error al enviar código MFA:', error);
    res.status(500).json({ success: false, error: 'Error al enviar código de verificación' });
  }
});

// Also update the verify-mfa endpoint
app.post('/verify-mfa', async (req, res) => {
  try {
    const { userId, code } = req.body;
    
    // Find the stored code using Firebase Firestore
    const mfaDoc = await admin.firestore().collection('mfaCodes').doc(userId).get();
    
    if (!mfaDoc.exists) {
      return res.status(400).json({ 
        success: false, 
        error: 'Código no encontrado o expirado' 
      });
    }
    
    const storedData = mfaDoc.data();
    const now = new Date();
    const expiresAt = storedData.expiresAt.toDate();
    
    // Check if code is expired
    if (now > expiresAt) {
      await admin.firestore().collection('mfaCodes').doc(userId).delete();
      return res.status(400).json({ 
        success: false, 
        error: 'Código expirado' 
      });
    }
    
    // Check if code matches
    if (storedData.code !== code) {
      return res.status(400).json({ 
        success: false, 
        error: 'Código incorrecto' 
      });
    }
    
    // Code is valid, delete it to prevent reuse
    await admin.firestore().collection('mfaCodes').doc(userId).delete();
    
    res.status(200).json({ success: true, message: 'Código verificado correctamente' });
  } catch (error) {
    console.error('Error al verificar código MFA:', error);
    res.status(500).json({ success: false, error: 'Error al verificar código' });
  }
});


// Update the SSE endpoint to properly handle the token and avoid header errors
app.get('/order-updates', async (req, res) => {
  try {
    // Get token from query parameter
    const token = req.query.token;
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    // Verify the token
    const decoded = jwt.verify(token, 'secretKey');
    const userId = decoded.uid;
    
    // Set headers for SSE
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });
    
    // Send initial connection message
    res.write(`data: ${JSON.stringify({ type: 'connection', message: 'Connected to order updates' })}\n\n`);
    
    // Store the client connection
    sseClients.set(userId, res);
    console.log(`SSE connection established for user ${userId}`);
    
    // Handle client disconnect
    req.on('close', () => {
      sseClients.delete(userId);
      console.log(`SSE connection closed for user ${userId}`);
    });
  } catch (error) {
    console.error('SSE connection error:', error);
    // Only send error response if headers haven't been sent yet
    if (!res.headersSent) {
      res.status(401).json({ error: 'Invalid token' });
    }
  }
});

// Update the sendOrderUpdate function to use the sseClients Map
const sendOrderUpdate = (userId, data) => {
  const client = sseClients.get(userId);
  if (client) {
    client.write(`data: ${JSON.stringify(data)}\n\n`);
    console.log(`Update sent to user ${userId}:`, data);
  } else {
    console.log(`No SSE connection for user ${userId}`);
  }
};

// ... rest of your code ...
// Add a new endpoint to update order status (for admin use)
app.post('/update-order-status', verifyToken, async (req, res) => {
  try {
    const { orderId, newStatus } = req.body;
    const adminId = req.user.uid;
    
    // Verify the user is an admin
    const adminDoc = await admin.firestore().collection('users').doc(adminId).get();
    const adminData = adminDoc.data();
    
    if (!adminData || adminData.rol !== 1) {
      return res.status(403).json({ error: 'No tienes permisos para realizar esta acción' });
    }
    
    // Update the order status
    const orderRef = admin.firestore().collection('ordenes').doc(orderId);
    const orderDoc = await orderRef.get();
    
    if (!orderDoc.exists) {
      return res.status(404).json({ error: 'Orden no encontrada' });
    }
    
    const orderData = orderDoc.data();
    
    // Update the status
    await orderRef.update({
      estado: newStatus,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Send real-time update to the customer
    sendOrderUpdate(orderData.userId, {
      type: 'order_updated',
      orderId,
      status: newStatus,
      message: `Tu pedido ha sido actualizado a: ${newStatus}`
    });
    
    res.json({ success: true, message: 'Estado de la orden actualizado' });
    
  } catch (error) {
    console.error('Error al actualizar estado de la orden:', error);
    res.status(500).json({ error: 'Error al actualizar estado de la orden' });
  }
});


app.get('/user-activities', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    
    // Get activities from Firestore
    const activitiesSnapshot = await db.collection('userActivities')
      .where('userId', '==', userId)
      .orderBy('timestamp', 'desc')
      .limit(50)
      .get();
    
    const activities = [];
    activitiesSnapshot.forEach(doc => {
      const data = doc.data();
      activities.push({
        id: doc.id,
        type: data.type,
        ...data.details,
        timestamp: data.timestamp ? data.timestamp.toDate() : new Date()
      });
    });
    
    res.json({ activities });
  } catch (error) {
    console.error('Error getting user activities:', error);
    res.status(500).json({ error: 'Error retrieving activity history' });
  }
});

// Add endpoint to log favorite activity
app.post('/log-activity', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { type, details } = req.body;
    
    if (!type) {
      return res.status(400).json({ error: 'Activity type is required' });
    }
    
    const activity = await logUserActivity(userId, type, details);
    
    res.json({ success: true, activity });
  } catch (error) {
    console.error('Error logging activity:', error);
    res.status(500).json({ error: 'Error logging activity' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
