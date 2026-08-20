/**
 * ============================================
 * SERVIDOR BACKEND - Tienda Chic
 * ============================================
 *
 * Ejecutar con: npm start
 *
 * Endpoints:
 *   POST /api/login          -> Valida credenciales, devuelve JWT
 *   POST /api/verificar-token -> Valida que un JWT sea válido
 *   GET  /                   -> Sirve el index.html (frontend)
 *
 * La contraseña NUNCA se almacena en texto plano en el servidor.
 * Se compara usando bcrypt contra el hash guardado en .env.
 */

require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// MIDDLEWARE
// ============================================

// Permitir solicitudes desde el frontend (mismo origen en producción)
app.use(cors());

// Parsear JSON en el body de las peticiones
app.use(express.json());

// Servir archivos estáticos (index.html, CSS, imágenes, etc.)
app.use(express.static(path.join(__dirname)));

// ============================================
// VARIABLES DE ENTORNO
// ============================================

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const JWT_EXPIRACION = '2h'; // Token válido por 2 horas

// Validar que las variables de entorno estén configuradas
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('ERROR CRITICO: JWT_SECRET no está configurado o es muy corto.');
    console.error('Genera una clave segura y agrégala en .env');
    process.exit(1);
}

if (!ADMIN_PASSWORD_HASH || ADMIN_PASSWORD_HASH.startsWith('$2b$10$Definitivamente')) {
    console.error('ERROR: ADMIN_PASSWORD_HASH no ha sido generado.');
    console.error('Ejecuta: npm run generar-hash');
    process.exit(1);
}

// ============================================
// ENDPOINTS DE AUTENTICACIÓN
// ============================================

/**
 * POST /api/login
 *
 * Recibe { password: "..." } y retorna:
 *   - 200 + { token, expiresIn } si la contraseña es correcta
 *   - 401 + { error } si es incorrecta
 *   - 400 + { error } si no se envía contraseña
 *
 * Flujo:
 *   1. Valida que el body tenga password
 *   2. Compara con bcrypt.compare() contra el hash de .env
 *   3. Si coincide, genera un JWT con 2h de expiración
 *   4. Devuelve el token al frontend
 */
app.post('/api/login', async (req, res) => {
    try {
        const { password } = req.body;

        // Validar que se envíe la contraseña
        if (!password || typeof password !== 'string') {
            return res.status(400).json({
                error: 'Debes enviar una contraseña válida.'
            });
        }

        // Comparar la contraseña ingresada contra el hash guardado
        // bcrypt.compare se encarga de extraer el salt del hash automáticamente
        const esValida = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

        if (!esValida) {
            return res.status(401).json({
                error: 'Contraseña incorrecta.'
            });
        }

        // Generar JWT con datos del admin
        const token = jwt.sign(
            {
                rol: 'admin',
                nombre: 'Administrador Tienda Chic'
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRACION }
        );

        console.log(`[LOGIN EXITOSO] ${new Date().toLocaleString()}`);

        res.status(200).json({
            token,
            expiresIn: JWT_EXPIRACION,
            mensaje: 'Acceso concedido.'
        });

    } catch (error) {
        console.error('Error en /api/login:', error);
        res.status(500).json({
            error: 'Error interno del servidor.'
        });
    }
});

/**
 * POST /api/verificar-token
 *
 * Recibe { token: "..." } y retorna:
 *   - 200 + { valido: true, datos } si el token es válido
 *   - 401 + { valido: false, error } si no lo es
 *
 * Flujo:
 *   1. Valida que se envíe token
 *   2. Intenta verificar con jwt.verify()
 *   3. Si es válido, retorna los datos del payload
 *   4. Si expiró o es inválido, retorna error
 *
 * Este endpoint se llama al cargar la página para saber
 * si la sesión del admin sigue activa.
 */
app.post('/api/verificar-token', (req, res) => {
    try {
        const { token } = req.body;

        if (!token || typeof token !== 'string') {
            return res.status(400).json({
                valido: false,
                error: 'Token no proporcionado.'
            });
        }

        // Verificar el token contra la misma clave secreta
        const datos = jwt.verify(token, JWT_SECRET);

        res.status(200).json({
            valido: true,
            datos: {
                rol: datos.rol,
                nombre: datos.nombre
            }
        });

    } catch (error) {
        // jwt.verify lanza errores específicos
        let mensaje = 'Token inválido.';

        if (error.name === 'TokenExpiredError') {
            mensaje = 'Token expirado. Inicia sesión nuevamente.';
        } else if (error.name === 'JsonWebTokenError') {
            mensaje = 'Token corrupto o inválido.';
        }

        res.status(401).json({
            valido: false,
            error: mensaje
        });
    }
});

/**
 * POST /api/cambiar-contrasena
 *
 * Recibe { token, contrasenaActual, contrasenaNueva }
 * y retorna:
 *   - 200 + { mensaje } si todo salió bien
 *   - 400/401/500 + { error } si algo falla
 *
 * Flujo:
 *   1. Verifica que el token JWT sea válido
 *   2. Valida la contraseña actual contra el hash de .env
 *   3. Genera hash nuevo con bcrypt
 *   4. Actualiza el archivo .env con el nuevo hash
 *   5. Devuelve confirmación
 *
 * NOTA: Esto actualiza el .env en disco. En producción
 * profesional se usaría una base de datos.
 */
app.post('/api/cambiar-contrasena', async (req, res) => {
    try {
        const { token, contrasenaActual, contrasenaNueva } = req.body;

        // 1. Verificar token
        if (!token) {
            return res.status(401).json({ error: 'Token requerido.' });
        }

        try {
            jwt.verify(token, JWT_SECRET);
        } catch (e) {
            return res.status(401).json({ error: 'Token inválido o expirado.' });
        }

        // 2. Validar campos
        if (!contrasenaActual || !contrasenaNueva) {
            return res.status(400).json({ error: 'Debes enviar contraseña actual y nueva.' });
        }

        if (contrasenaNueva.length < 6) {
            return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
        }

        // 3. Verificar contraseña actual
        const esValida = await bcrypt.compare(contrasenaActual, ADMIN_PASSWORD_HASH);
        if (!esValida) {
            return res.status(401).json({ error: 'La contraseña actual no es correcta.' });
        }

        // 4. Generar hash de la nueva contraseña
        const nuevoHash = await bcrypt.hash(contrasenaNueva, 10);

        // 5. Actualizar .env en disco
        const fs = require('fs');
        const envPath = __dirname + '/.env';
        let envContent = fs.readFileSync(envPath, 'utf8');
        envContent = envContent.replace(
            /ADMIN_PASSWORD_HASH=.*/,
            `ADMIN_PASSWORD_HASH=${nuevoHash}`
        );
        fs.writeFileSync(envPath, envContent, 'utf8');

        // 6. Recargar la variable en memoria
        process.env.ADMIN_PASSWORD_HASH = nuevoHash;

        console.log(`[CONTRASEÑA CAMBIADA] ${new Date().toLocaleString()}`);

        res.status(200).json({
            mensaje: 'Contraseña actualizada correctamente.'
        });

    } catch (error) {
        console.error('Error en /api/cambiar-contrasena:', error);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// ============================================
// RUTA CATCH-ALL: Sirve index.html para cualquier otra ruta
// ============================================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, () => {
    console.log('\n============================================');
    console.log('  TIENDA CHIC - Servidor Activo');
    console.log('============================================');
    console.log(`  URL:          http://localhost:${PORT}`);
    console.log(`  Login API:    http://localhost:${PORT}/api/login`);
    console.log(`  Token API:    http://localhost:${PORT}/api/verificar-token`);
    console.log(`  JWT Expira:   ${JWT_EXPIRACION}`);
    console.log(`  Hash Cargado: ${ADMIN_PASSWORD_HASH.substring(0, 20)}...`);
    console.log('============================================\n');
});
