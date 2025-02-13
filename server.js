const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); 
require('dotenv').config();
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');


const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

// Configuración de Multer para carga de archivos
const storage = multer.memoryStorage();
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Máximo 5MB
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Solo se permiten archivos de imagen'));
        }
        cb(null, true);
    }
});


const allowedOrigins = ['http://localhost:5173', 'https://toolregcon.vercel.app']; 

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());
app.use(helmet());

// Configuración de conexión a Supabase PostgreSQL
const pool = new Pool({
    host: process.env.DB_HOST, // Cambia esto a tu variable de entorno
    user: process.env.DB_USER, // Cambia esto a tu variable de entorno
    password: process.env.DB_PASSWORD, // Cambia esto a tu variable de entorno
    database: process.env.DB_NAME, // Cambia esto a tu variable de entorno
    port: process.env.DB_PORT || 5432, // Cambia esto a tu variable de entorno
    ssl: { rejectUnauthorized: false }
});

async function query(sql, params = []) {
    const client = await pool.connect();
    try {
        const result = await client.query(sql, params);
        return result.rows;
    } finally {
        client.release();
    }
}

// Verifica la conexión a la base de datos
pool.connect((err) => {
    if (err) {
        console.error('Error al conectar con la base de datos de Supabase:', err.message);
    } else {
        console.log('Conectado a la base de datos de Supabase PostgreSQL.');
    }
});

// Cerrar la conexión cuando se detiene el proceso
process.on('SIGINT', () => {
    pool.end(() => {
        console.log('Conexión a PostgreSQL cerrada.');
        process.exit(0);
    });
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // Máximo 5 intentos
    message: { error: "Demasiados intentos de inicio de sesión. Inténtalo más tarde." }
});

const authenticateToken = (req, res, next) => {
    try {
        // Intentar obtener el token desde el encabezado Authorization
        const authHeader = req.headers['authorization'];
        const tokenFromHeader = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer <token>"

        // Intentar obtener el token desde la cookie
        const tokenFromCookie = req.cookies.token;

        // Usar el token del encabezado si está presente, de lo contrario usar el de la cookie
        const token = tokenFromHeader || tokenFromCookie;

        if (!token) {
            return res.status(401).json({ error: "No autorizado, token faltante" });
        }

        // Verificar el token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Validar que el token contenga los datos necesarios
        if (!decoded.id || !decoded.userType || !decoded.workgroup_id) { // 👀 Asegúrate de validar workgroup_id
            return res.status(403).json({ error: "Token inválido, datos insuficientes" });
        }

        req.user = decoded; // Guardar los datos en la request para uso posterior
        next();
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "Token expirado, inicie sesión nuevamente" });
        } else {
            return res.status(403).json({ error: "Token inválido" });
        }
    }
};

module.exports = authenticateToken;

/***************************************************************
 *                 VERIFICAR LAS SESIONES
 ***************************************************************/
app.get('/auth/status', authenticateToken, (req, res) => {
    const token = req.cookies.token; // Obtener el token desde la cookie

    if (!token) {
        return res.status(401).json({ authenticated: false, error: "No autorizado" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ 
            authenticated: true, 
            user_id: decoded.id, 
            workgroup_id: decoded.workgroup_id, 
            role_id: decoded.role_id 
        });
    } catch (error) {
        res.status(401).json({ authenticated: false, error: "Token inválido" });
    }
});


/***************************************************************
 *                        SUBIR IMAGENES
 * ************************************************************/
app.post('/upload', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se ha enviado ninguna imagen' });
        }

        // Convierte la imagen a Base64
        const fs = require('fs');
        const imageBuffer = fs.readFileSync(req.file.path);
        const imageBase64 = imageBuffer.toString('base64');

        // Llamada a la API de ImgBB
        const imgbbApiKey = process.env.IMGBB_API_KEY;
        const response = await axios.post('https://api.imgbb.com/1/upload', null, {
            params: {
                key: imgbbApiKey,
                image: imageBase64
            }
        });

        // Borra el archivo temporal después de subirlo
        fs.unlinkSync(req.file.path);

        // Responde con la URL de la imagen subida
        res.json({ url: response.data.data.url });
    } catch (error) {
        console.error('Error al subir la imagen:', error);
        res.status(500).json({ error: 'Error al subir la imagen' });
    }
});


/***************************************************************
 * 
 * 
 * 
 *                ENPOINTS PARA ADMINISTRADORES
 * 
 * 
 * 
 * ************************************************************/

/***************************************************************
 *                CONTROL DE USUARIOS
 * ************************************************************/
app.get('/users', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM Users');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const rows = await query('SELECT * FROM Users WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'User not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/users', async (req, res) => {
    const { first_name, last_name, email, phone, password, birthday} = req.body;

    if (!password || password.length < 8) {
        return res.status(400).json({ 
            error: 'La contraseña es requerida y debe tener al menos 8 caracteres.' 
        });
    }

    try {
        // Encriptar la contraseña proporcionada por el usuario
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insertar el usuario en la base de datos
        const rows = await query(
            'INSERT INTO Users (first_name, last_name, email, phone, password, birthday) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [first_name, last_name, email, phone, hashedPassword, birthday]
        );

        res.json({ 
            message: 'Usuario registrado exitosamente.', 
            data: rows[0] 
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


app.put('/users/:id', async (req, res) => {
    const { first_name, last_name, email, phone, password } = req.body;
    const { id } = req.params;

    try {
        // Si se proporciona una nueva contraseña, encríptala
        let hashedPassword;
        if (password) {
            hashedPassword = await bcrypt.hash(password, saltRounds);
        }

        const rows = await query(
            `UPDATE Users SET first_name = $1, last_name = $2, email = $3, phone = $4, password = $5 WHERE id = $6 RETURNING *`,
            [first_name, last_name, email, phone, hashedPassword || null, id] // Si no hay nueva contraseña, se establece como null
        );

        if (rows.length === 0) return res.status(404).json({ message: 'User not found' });
        res.json({ message: 'User updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/users/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('DELETE FROM Users WHERE id = $1 RETURNING id', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'User not found' });
        res.json({ message: 'User deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/***************************************************************
 *                CONTROL DE EVENTOS SIN WORKGROUP
 * ************************************************************/
app.post('/events', async (req, res) => {
    const { name, event_date, location, description, workgroup_id, event_category, is_online } = req.body;
    try {
        const rows = await query(
            'INSERT INTO Events (name, event_date, location, description, workgroup_id, event_category, is_online ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [name, event_date, location, description, workgroup_id, image, event_category, is_online ]
        );
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/events', async (req, res) => {
    try {
        // Obtener los parámetros de paginación (con valores por defecto)
        const limit = parseInt(req.query.limit) || 10; // Por defecto, 100 registros por página
        const offset = parseInt(req.query.offset) || 0; // Por defecto, empieza desde el primer registro

        // Consulta SQL con paginación
        const queryText = 'SELECT * FROM Events ORDER BY id LIMIT $1 OFFSET $2';
        const queryParams = [limit, offset];

        // Ejecutar la consulta
        const rows = await query(queryText, queryParams); // Cambio aquí: no desestructurar

        // Verificar si hay datos
        if (!rows || rows.length === 0) {
            return res.status(404).json({ message: 'No se encontraron eventos.' });
        }

        // Devolver los datos paginados
        res.json({
            message: 'Success',
            data: rows, // Asegúrate de que los datos estén aquí
            pagination: {
                limit: limit,
                offset: offset,
                next_offset: offset + limit
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/events', async (req, res) => {
    const { workgroup_id, limit, offset } = req.query; // Obtén los parámetros de la consulta

    try {
        // Convertir limit y offset a números (con valores por defecto)
        const paginationLimit = parseInt(limit) || 10; // Por defecto, 100 registros por página
        const paginationOffset = parseInt(offset) || 0; // Por defecto, empieza desde el primer registro

        // Consulta SQL con paginación y filtro por workgroup_id
        const queryText = `
            SELECT * FROM Events 
            WHERE workgroup_id = $1 
            ORDER BY id 
            LIMIT $2 OFFSET $3
        `;
        const queryParams = [workgroup_id, paginationLimit, paginationOffset];

        // Ejecutar la consulta
        const rows = await query(queryText, queryParams);

        // Verificar si hay datos
        if (!rows || rows.length === 0) {
            return res.status(404).json({ message: 'No se encontraron eventos para el grupo de trabajo especificado.' });
        }

        // Devolver los datos paginados
        res.json({
            message: 'Success',
            data: rows,
            pagination: {
                limit: paginationLimit,
                offset: paginationOffset,
                next_offset: paginationOffset + paginationLimit
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.get('/events/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('SELECT * FROM Events WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Event not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/events/:id', async (req, res) => {
    const { name, event_date, location, description, category_id, workgroup_id, event_category, is_online } = req.body;
    const { id } = req.params;
    try {
        const rows = await query(
            `UPDATE Events SET name = $1, event_date = $2, location = $3, description = $4, category_id = $5, workgroup_id = $6, event_category = $7, is_online = $8 WHERE id = $9 RETURNING *`,
            [name, event_date, location, description, category_id, workgroup_id, event_category, is_online, id]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Event not found' });
        res.json({ message: 'Event updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/events/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('DELETE FROM Events WHERE id = $1 RETURNING id', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Event not found' });
        res.json({ message: 'Event deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
/***************************************************************
 *                VISTA DE IMAGENES DE EVENTOS
 * ************************************************************/
app.post('/events/:id/upload-image', upload.single('image'), async (req, res) => {
    const eventId = req.params.id;

    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se ha enviado ninguna imagen' });
        }

        // Convierte la imagen a Base64 directamente desde el buffer
        const imageBase64 = req.file.buffer.toString('base64');

        // Sube la imagen a ImgBB
        const imgbbApiKey = process.env.IMGBB_API_KEY;
        const response = await axios.post('https://api.imgbb.com/1/upload', null, {
            params: {
                key: imgbbApiKey,
                image: imageBase64
            }
        });

        if (!response.data.success) {
            throw new Error('Error al subir la imagen a ImgBB');
        }

        // Obtiene la URL de la imagen subida
        const imageUrl = response.data.data.url;

        // Actualiza la base de datos con la nueva imagen
        const updatedEvent = await query(
            'UPDATE Events SET image = $1 WHERE id = $2 RETURNING *',
            [imageUrl, eventId]
        );

        res.json({ message: 'Imagen subida y evento actualizado exitosamente', data: updatedEvent[0] });
    } catch (error) {
        console.error('Error al subir la imagen:', error);
        res.status(500).json({ error: 'Error al subir la imagen', details: error.message });
    }
});

app.put('/events/:id/update-image', upload.single('image'), async (req, res) => {
    const eventId = req.params.id;

    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se ha enviado ninguna imagen' });
        }

        // Convierte la imagen a Base64 directamente desde el buffer
        const imageBase64 = req.file.buffer.toString('base64');

        // Sube la nueva imagen a ImgBB
        const imgbbApiKey = process.env.IMGBB_API_KEY;
        const response = await axios.post('https://api.imgbb.com/1/upload', null, {
            params: {
                key: imgbbApiKey,
                image: imageBase64
            },
            timeout: 10000 // Aumenta el timeout a 10 segundos
        });

        if (!response.data.success) {
            throw new Error('Error al subir la imagen a ImgBB');
        }

        // Obtiene la URL de la nueva imagen subida
        const newImageUrl = response.data.data.url;

        // Actualiza la base de datos con la nueva imagen
        const updatedEvent = await query(
            'UPDATE Events SET image = $1 WHERE id = $2 RETURNING *',
            [newImageUrl, eventId]
        );

        res.json({ message: 'Imagen actualizada exitosamente', data: updatedEvent[0] });
    } catch (error) {
        console.error('Error al actualizar la imagen:', error);
        if (error.response) {
            // El servidor respondió con un código de estado fuera del rango 2xx
            console.error('Datos del error:', error.response.data);
            console.error('Código de estado:', error.response.status);
            console.error('Cabeceras:', error.response.headers);
        } else if (error.request) {
            // La solicitud fue hecha pero no se recibió respuesta
            console.error('No se recibió respuesta del servidor:', error.request);
        } else {
            // Algo sucedió en la configuración de la solicitud que provocó un error
            console.error('Error al configurar la solicitud:', error.message);
        }
        res.status(500).json({ error: 'Error al actualizar la imagen', details: error.message });
    }
});


/***************************************************************
 *                VISTA DE EVENTOS SIN WORKGROUP
 * ************************************************************/
app.get('/all-events', async (req, res) => {
    try {
        // Obtener los parámetros de paginación (con valores por defecto)
        const limit = parseInt(req.query.limit) || 10; // Por defecto, 100 registros por página
        const offset = parseInt(req.query.offset) || 0; // Por defecto, empieza desde el primer registro

        // Consulta SQL con paginación
        const queryText = 'SELECT * FROM event_details ORDER BY event_id LIMIT $1 OFFSET $2';
        const queryParams = [limit, offset];

        // Ejecutar la consulta
        const rows = await query(queryText, queryParams); // Cambio aquí: no desestructurar

        // Verificar si hay datos
        if (!rows || rows.length === 0) {
            return res.status(404).json({ message: 'No se encontraron eventos.' });
        }

        // Devolver los datos paginados
        res.json({
            message: 'Success',
            data: rows, // Asegúrate de que los datos estén aquí
            pagination: {
                limit: limit,
                offset: offset,
                next_offset: offset + limit
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/all-events', async (req, res) => {
    const { workgroup_id, limit, offset } = req.query; // Obtén los parámetros de la consulta

    try {
        // Convertir limit y offset a números (con valores por defecto)
        const paginationLimit = parseInt(limit) || 10; // Por defecto, 100 registros por página
        const paginationOffset = parseInt(offset) || 0; // Por defecto, empieza desde el primer registro

        // Consulta SQL con paginación y filtro por workgroup_id
        const queryText = `
            SELECT * FROM event_details
            WHERE workgroup_id = $1 
            ORDER BY event_id 
            LIMIT $2 OFFSET $3
        `;
        const queryParams = [workgroup_id, paginationLimit, paginationOffset];

        // Ejecutar la consulta
        const rows = await query(queryText, queryParams);

        // Verificar si hay datos
        if (!rows || rows.length === 0) {
            return res.status(404).json({ message: 'No se encontraron eventos para el grupo de trabajo especificado.' });
        }

        // Devolver los datos paginados
        res.json({
            message: 'Success',
            data: rows,
            pagination: {
                limit: paginationLimit,
                offset: paginationOffset,
                next_offset: paginationOffset + paginationLimit
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.get('/event-detail/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('SELECT * FROM event_details WHERE event_id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Event not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/***************************************************************
 *                VISTA DE EVENTOS SIN WORKGROUP
 * ************************************************************/
app.post('/event-categories', async (req, res) => {
    const { name, description } = req.body;
    try {
        const rows = await query(
            'INSERT INTO eventcategories (name, description) VALUES ($1, $2) RETURNING *',
            [name, description]
        );
        res.json({ message: 'Event category created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/event-categories', async (req, res) => {
    try {
        // Obtener los parámetros de paginación (con valores por defecto)
        const limit = parseInt(req.query.limit) || 100; // Por defecto, 100 registros por página
        const offset = parseInt(req.query.offset) || 0; // Por defecto, empieza desde el primer registro

        // Consulta SQL con paginación
        const queryText = 'SELECT * FROM eventcategories ORDER BY id LIMIT $1 OFFSET $2';
        const queryParams = [limit, offset];

        // Ejecutar la consulta
        const rows = await query(queryText, queryParams); // Cambio aquí: no desestructurar

        // Verificar si hay datos
        if (!rows || rows.length === 0) {
            return res.status(404).json({ message: 'No se encontraron categorias de eventos.' });
        }

        // Devolver los datos paginados
        res.json({
            message: 'Success',
            data: rows, // Asegúrate de que los datos estén aquí
            pagination: {
                limit: limit,
                offset: offset,
                next_offset: offset + limit
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/***************************************************************
 *                CONTROL DE TICKECTS CATEGORIES
 * ************************************************************/
app.post('/ticket-categories', async (req, res) => {
    const { name, price, description, workgroup_id } = req.body;
    try {
        const rows = await query(
            'INSERT INTO TicketCategories (name, price, description, workgroup_id) VALUES ($1, $2, $3, $4) RETURNING *',
            [name, price, description, workgroup_id]
        );
        res.json({ message: 'Ticket category created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/ticket-categories', async (req, res) => {
    const { workgroup_id } = req.query; // Obtener el workgroup_id de la consulta

    try {
        const rows = await query('SELECT * FROM TicketCategories WHERE workgroup_id = $1', [workgroup_id]);
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.get('/ticket-categories/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('SELECT * FROM TicketCategories WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket category not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/ticket-categories/:id', async (req, res) => {
    const { id } = req.params;
    const { name, price, description, workgroup_id } = req.body;
    try {
        const rows = await query(
            `UPDATE TicketCategories SET name = $1, price = $2, description = $3, workgroup_id = $4 WHERE id = $5 RETURNING *`,
            [name, price, description, workgroup_id, id]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket category not found' });
        res.json({ message: 'Ticket category updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/ticket-categories/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('DELETE FROM TicketCategories WHERE id = $1 RETURNING id', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket category not found' });
        res.json({ message: 'Ticket category deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/***************************************************************
 *         CONTROL DE RELACIONES DE TICKETS Y EVENTOS
 * ************************************************************/
app.post('/ticket-events', async (req, res) => {
    const { event_id, ticketcategory_id } = req.body;

    try {
        // Verificar si el boleto ya está asignado a un evento
        const existingRelation = await query(
            'SELECT * FROM eventtickets WHERE ticketcategory_id = $1',
            [ticketcategory_id]
        );

        if (existingRelation.length > 0) {
            return res.status(400).json({
                error: 'El boleto ya está asignado a otro evento',
                assigned_event_id: existingRelation[0].event_id // Información opcional para el cliente
            });
        }

        // Si no está asignado, insertar la nueva relación
        const rows = await query(
            'INSERT INTO eventtickets (event_id, ticketcategory_id) VALUES ($1, $2) RETURNING *',
            [event_id, ticketcategory_id]
        );

        res.json({ message: 'Boletos asignados correctamente a un evento', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Error del servidor', details: error.message });
    }
});

app.get('/ticket-events', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM eventtickets');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/ticket-events/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('DELETE FROM eventtickets WHERE ticketcategory_id = $1 RETURNING *', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket not found' });
        res.json({ message: 'Relación de boletos y eventos eliminada correctamente', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/ticket-events/:id', async (req, res) => {
    const { id } = req.params; // `id` corresponde a `ticketcategory_id`
    const { event_id } = req.body; // Nuevo `event_id` al que se asignará el boleto

    try {
        // Verificar si el boleto ya está relacionado con el evento especificado
        const existingRelation = await query(
            'SELECT * FROM eventtickets WHERE ticketcategory_id = $1',
            [id]
        );

        if (existingRelation.length === 0) {
            return res.status(404).json({ error: 'Relación no encontrada' });
        }

        // Verificar si el boleto ya está asignado al nuevo evento
        const duplicateCheck = await query(
            'SELECT * FROM eventtickets WHERE ticketcategory_id = $1 AND event_id = $2',
            [id, event_id]
        );

        if (duplicateCheck.length > 0) {
            return res.status(400).json({ error: 'El boleto ya está asignado al evento especificado' });
        }

        // Actualizar la relación
        const rows = await query(
            'UPDATE eventtickets SET event_id = $1 WHERE ticketcategory_id = $2 RETURNING *',
            [event_id, id]
        );

        res.json({
            message: 'Relación de boleto y evento actualizada correctamente',
            data: rows[0]
        });
    } catch (error) {
        res.status(500).json({ error: 'Error del servidor', details: error.message });
    }
});

app.get('/ticket-events/:event_id', async (req, res) => {
    const { event_id } = req.params; // ID del evento

    try {
        // Consultar los boletos relacionados con el evento
        const rows = await query(
            `SELECT * 
             FROM eventtickets 
             WHERE event_id = $1`,
            [event_id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: 'No se encontraron boletos relacionados con este evento'
            });
        }

        res.json({
            message: 'Boletos relacionados con el evento encontrados',
            data: rows
        });
    } catch (error) {
        res.status(500).json({ error: 'Error del servidor', details: error.message });
    }
});


/***************************************************************
 *                CONTROL DE BOLETOS SIN WORKGROUP
 * ************************************************************/
app.get('/tickets', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM Tickets');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/tickets/:code', async (req, res) => {
    const { code } = req.params;
    try {
        const rows = await query('SELECT * FROM Tickets WHERE code = $1', [code]);
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/tickets', async (req, res) => {
    const { code, name, category_id, status, workgroup_id } = req.body;
    try {
        const rows = await query(
            'INSERT INTO Tickets (code, name, category_id, status, workgroup_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [code, name, category_id, status, workgroup_id]
        );
        res.json({ message: 'Ticket created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/tickets/:code', async (req, res) => {
    const { code } = req.params;
    const { name, category_id, status, workgroup_id } = req.body;
    try {
        const rows = await query(
            `UPDATE Tickets SET name = $1, category_id = $2, status = $3, workgroup_id = $4 WHERE code = $5 RETURNING *`,
            [name, category_id, status, workgroup_id, code]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket not found' });
        res.json({ message: 'Ticket updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/tickets/:code', async (req, res) => {
    const { code } = req.params;
    try {
        const rows = await query('DELETE FROM Tickets WHERE code = $1 RETURNING code', [code]);
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket not found' });
        res.json({ message: 'Ticket deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


/***************************************************************
 *              VISTA DE TICKETS CON INFORMACIÓN
 * ************************************************************/
app.get('/ticket-view', async (req, res) => {
    const { workgroup_id } = req.query; // Obtener ambos parámetros de consulta

    try {
        // Filtrar tickets según el workgroup_id y el ticket_code
        const rows = await query('SELECT * FROM TicketFullInfo WHERE workgroup_id = $1', [workgroup_id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket not found for this workgroup' });
        res.json({ message: 'Success', data: rows[0] }); // Regresar solo un ticket
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/ticket-view-code', async (req, res) => {
    const { ticket_code, workgroup_id } = req.query; // Obtener ambos parámetros de consulta

    try {
        // Filtrar tickets según el workgroup_id y el ticket_code
        const rows = await query('SELECT * FROM TicketFullInfo WHERE code = $1 AND workgroup_id = $2', [ticket_code, workgroup_id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket not found for this workgroup' });
        res.json({ message: 'Success', data: rows[0] }); // Regresar solo un ticket
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.get('/ticket-view-code/:code', async (req, res) => {
    const { code } = req.params;
    const workgroupId = req.query.workgroup_id; // Obtener el workgroup_id de la consulta

    try {
        const rows = await query('SELECT * FROM TicketFullInfo WHERE code = $1 AND workgroup_id = $2', [code, workgroupId]);
        if (rows.length === 0) return res.status(404).json({ message: 'Este boleto no existe o es inválido.' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.get('/ticket-view/:code', async (req, res) => {
    const workgroupId = req.query.workgroup_id; // Obtener el workgroup_id de la consulta

    try {
        const rows = await query('SELECT * FROM TicketFullInfo WHERE workgroup_id = $1', [workgroupId]);
        if (rows.length === 0) return res.status(404).json({ message: 'Este boleto no existe o es inválido.' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/***************************************************************
 *           CONTROL DE ASISTENCIAS SIN WORKGROUP
 * ************************************************************/
app.get('/attendance', async (req, res) => {
    const { ticket_code, workgroup_id } = req.query; // Obtener parámetros de consulta

    try {
        const rows = await query('SELECT * FROM Attendance WHERE ticket_code = $1 AND workgroup_id = $2', [ticket_code, workgroup_id]);
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/attendance/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('SELECT * FROM Attendance WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Attendance not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/attendance', async (req, res) => {
    const { user_id, event_id, ticket_code, workgroup_id } = req.body;
    try {
        // Verificar el estado del boleto
        const ticketRows = await query('SELECT status FROM Tickets WHERE code = $1', [ticket_code]);
        if (ticketRows.length === 0 || ticketRows[0].status !== 'Sin Usar') {
            return res.status(400).json({ error: 'Este boleto es inválido o ya ha sido usado.' });
        }

        // Crear el registro de asistencia
        const rows = await query(
            'INSERT INTO Attendance (user_id, event_id, ticket_code, workgroup_id) VALUES ($1, $2, $3, $4) RETURNING *',
            [user_id, event_id, ticket_code, workgroup_id]
        );
        res.json({ message: 'Attendance created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/attendance/:id', async (req, res) => {
    const { user_id, event_id, ticket_code, workgroup_id } = req.body;
    const { id } = req.params;
    try {
        const rows = await query(
            `UPDATE Attendance SET user_id = $1, event_id = $2, ticket_code = $3, workgroup_id = $4 WHERE id = $5 RETURNING *`,
            [user_id, event_id, ticket_code, workgroup_id, id]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Attendance not found' });
        res.json({ message: 'Attendance updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/attendance-status/:id', async (req, res) => {
    const { status } = req.body; // Solo se obtiene el nuevo estado
    const { id } = req.params;

    try {
        // Actualizar solo el estado en la asistencia, manteniendo los demás campos intactos
        const rows = await query(
            `UPDATE Attendance SET status = $1 WHERE id = $2 RETURNING *`,
            [status, id]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Attendance not found' });
        res.json({ message: 'Attendance updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/attendance/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('DELETE FROM Attendance WHERE id = $1 RETURNING id', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Attendance not found' });
        res.json({ message: 'Attendance deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/***************************************************************
 *        VISTA DE INFORMACIÓN COMPLETA DE ASISTENCIA
 * ************************************************************/
app.get('/attendance-info', async (req, res) => {
    const { workgroup_id } = req.query; // Obtener el workgroup_id de la consulta

    try {
        const rows = await query('SELECT * FROM attendancedetails WHERE workgroup_id = $1', [workgroup_id]); // Filtrar por workgroup_id
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/attendance-info/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('SELECT * FROM AttendanceDetails WHERE attendance_id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Attendance not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/***************************************************************
 *          VISTA DE BOLETOS Y CANTIDAD DE LOS MISMOS
 * ************************************************************/
app.get('/ticket-categories-with-counts', async (req, res) => {
    const { workgroup_id } = req.query; // Obtener el workgroup_id de la consulta

    try {
        const rows = await query('SELECT * FROM TicketCategoriesWithCounts WHERE workgroup_id = $1', [workgroup_id]);
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/ticket-categories-with-counts/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('SELECT * FROM TicketCategoriesWithCounts WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Ticket category not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/***************************************************************
 *         VER LOS BOLETOS DE UNA CATEGORIA ESPECIFICA
 * ************************************************************/
app.get('/tickets/category/:category_id', async (req, res) => {
    const { category_id } = req.params;
    try {
        const rows = await query('SELECT * FROM Tickets WHERE category_id = $1', [category_id]);
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/***************************************************************
 *                CONTROL DE GRUPOS DE TRABAJO
 * ************************************************************/
app.get('/workgroups', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM WorkGroups');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/workgroups/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('SELECT * FROM WorkGroups WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Work group not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/workgroups', async (req, res) => {
    const { name, description } = req.body;
    try {
        const rows = await query(
            'INSERT INTO WorkGroups (name, description) VALUES ($1, $2) RETURNING *',
            [name, description]
        );
        res.json({ message: 'Work group created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/workgroups/:id', async (req, res) => {
    const { id } = req.params;
    const { name, description } = req.body;
    try {
        const rows = await query(
            `UPDATE WorkGroups SET name = $1, description = $2 WHERE id = $3 RETURNING *`,
            [name, description, id]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Work group not found' });
        res.json({ message: 'Work group updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/workgroups/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('DELETE FROM WorkGroups WHERE id = $1 RETURNING id', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Work group not found' });
        res.json({ message: 'Work group deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Obtener todos los registros de la vista usersmembership
app.get('/usersmembership', async (req, res) => {
    const { workgroup_id } = req.query; // Obtener el workgroup_id de la consulta

    try {
        const rows = await query('SELECT * FROM usersmembership WHERE workgroup_id = $1', [workgroup_id]); // Filtrar por workgroup_id
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obtener todos los registros de la vista workgroupdetails
app.get('/workgroupdetails', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM workgroupdetails');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/workgroupdetails/:workgroup_id', async (req, res) => {
    const { workgroup_id } = req.params;
    try {
        const rows = await query('SELECT * FROM workgroupdetails WHERE workgroup_id = $1', [workgroup_id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Work group details not found' });
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Endpoints para membresías
app.get('/membership', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM membership');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/membership/:workgroup_id/:admin_id', async (req, res) => {
    const { workgroup_id, admin_id } = req.params;
    try {
        const rows = await query('SELECT * FROM membership WHERE workgroup_id = $1 AND admin_id = $2', [workgroup_id, admin_id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Membership not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/membership', async (req, res) => {
    const { workgroup_id, admin_id, role_id } = req.body;
    try {
        const rows = await query(
            'INSERT INTO membership (workgroup_id, admin_id, role_id) VALUES ($1, $2, $3) RETURNING *',
            [workgroup_id, admin_id, role_id]
        );
        res.json({ message: 'Membership created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/membership/:workgroup_id/:admin_id', async (req, res) => {
    const { workgroup_id, admin_id } = req.params;
    const { role_id } = req.body;
    try {
        const rows = await query(
            'UPDATE membership SET role_id = $1 WHERE workgroup_id = $2 AND admin_id = $3 RETURNING *',
            [role_id, workgroup_id, admin_id]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Membership not found' });
        res.json({ message: 'Membership updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/membership/:workgroup_id/:admin_id', async (req, res) => {
    const { workgroup_id, admin_id } = req.params;
    try {
        const rows = await query('DELETE FROM membership WHERE workgroup_id = $1 AND admin_id = $2 RETURNING workgroup_id, admin_id', [workgroup_id, admin_id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Membership not found' });
        res.json({ message: 'Membership deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/***************************************************************
 *                CONTROL DE ADMINISTRADORES
 * ************************************************************/
app.get('/admin', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM Admin');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/admin/:id', async (req, res) => {
    try {
        console.log('Cookies recibidas:', req.cookies); // 👀 Imprime las cookies en la consola
        const { id } = req.params;
        const workgroupId = req.cookies.workgroup_id; // Obtener workgroup_id de la cookie

        if (!workgroupId) {
            return res.status(403).json({ message: 'No autorizado: Falta workgroup_id' });
        }

        const adminData = await db.query(
            'SELECT * FROM admin WHERE id = $1 AND workgroup_id = $2',
            [id, workgroupId]
        );

        if (adminData.rowCount === 0) {
            return res.status(404).json({ message: 'Administrador no encontrado' });
        }

        res.json({ data: adminData.rows[0] });
    } catch (error) {
        console.error('Error al obtener perfil del administrador:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});




app.post('/admin', async (req, res) => {
    const { first_name, last_name, email, phone, description, password } = req.body;
    try {
        const rows = await query(
            'INSERT INTO Admin (first_name, last_name, email, phone, description, password) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [first_name, last_name, email, phone, description, password]
        );
        res.json({ message: 'Admin created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/admin/:id', async (req, res) => {
    const { id } = req.params;
    const { first_name, last_name, email, phone, description, password } = req.body;
    try {
        const rows = await query(
            `UPDATE Admin SET first_name = $1, last_name = $2, email = $3, phone = $4, description = $5, password = $6 WHERE id = $7 RETURNING *`,
            [first_name, last_name, email, phone, description, password, id]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Admin not found' });
        res.json({ message: 'Admin updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/admin/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('DELETE FROM Admin WHERE id = $1 RETURNING id', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Admin not found' });
        res.json({ message: 'Admin deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/admin-login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    try {
        // Buscar al administrador
        const admin = await query('SELECT * FROM Admin WHERE email = $1', [email]);

        if (admin.length === 0) {
            return res.status(401).json({ error: 'Correo o contraseña inválidos' });
        }

        // Verificar la contraseña
        const isMatch = await bcrypt.compare(password, admin[0].password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Correo o contraseña inválidos' });
        }

        // Obtener grupo de trabajo y rol
        const membership = await query('SELECT workgroup_id, role_id FROM membership WHERE admin_id = $1', [admin[0].id]);

        if (membership.length === 0) {
            return res.status(403).json({ error: "No tienes permisos para acceder a un grupo de trabajo." });
        }

        const { workgroup_id, role_id } = membership[0];

        // Crear un token con información extra
        const token = jwt.sign(
            { 
                id: admin[0].id, 
                userType: "admin", 
                workgroup_id, 
                role_id 
            },
            process.env.JWT_SECRET, 
            { expiresIn: '8h' }
        );

        // Establecer el token en una cookie segura (para la web)
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", // En producción, se usa HTTPS
            sameSite: "Lax"
        });

        // Enviar el token en el cuerpo de la respuesta (para móvil)
        res.json({ 
            message: 'Inicio de sesión exitoso', 
            token, // Envía el token aquí
            workgroup_id, 
            role_id, 
            user_id: admin[0].id 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

/***************************************************************
 *                CONTROL DE ROLES
 * ************************************************************/
app.get('/roles', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM Roles');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/roles/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('SELECT * FROM Roles WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Role not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/roles', async (req, res) => {
    const { name, description } = req.body;
    try {
        const rows = await query(
            'INSERT INTO Roles (name, description) VALUES ($1, $2) RETURNING *',
            [name, description]
        );
        res.json({ message: 'Role created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/roles/:id', async (req, res) => {
    const { id } = req.params;
    const { name, description } = req.body;
    try {
        const rows = await query(
            `UPDATE Roles SET name = $1, description = $2 WHERE id = $3 RETURNING *`,
            [name, description, id]
        );
        if (rows.length === 0) return res.status(404).json({ message: 'Role not found' });
        res.json({ message: 'Role updated successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/roles/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await query('DELETE FROM Roles WHERE id = $1 RETURNING id', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Role not found' });
        res.json({ message: 'Role deleted successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


/***************************************************************
 *            ESTADISTICAS DE EVENTOS Y ASISTENCIAS
 * ************************************************************/
// Endpoint para obtener el resumen de asistencia filtrando por workgroup_id y event_id
app.get('/eventattendancesummary', async (req, res) => {
    const workgroupId = req.query.workgroup_id; // Obtener workgroup_id de la query
    const eventId = req.query.event_id; // Obtener event_id de la query

    try {
        // Composición de la consulta
        const queryText = 'SELECT * FROM eventattendancesummary WHERE workgroup_id = $1' + 
                          (eventId ? ' AND event_id = $2' : '');
        const queryParams = eventId ? [workgroupId, eventId] : [workgroupId];

        const rows = await query(queryText, queryParams);
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Endpoint para obtener resumen de asistencia por event_id
app.get('/eventattendancesummary/:event_id', async (req, res) => {
    const { event_id } = req.params;
    const workgroupId = req.query.workgroup_id; // Obtener workgroup_id de la query

    try {
        const rows = await query('SELECT * FROM eventattendancesummary WHERE event_id = $1 AND workgroup_id = $2', [event_id, workgroupId]);
        if (rows.length === 0) return res.status(404).json({ message: 'Event attendance summary not found' });
        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/***************************************************************
 *             CONTROL DE PÁGINAS DE EVENTOS
 * ************************************************************/
app.get('/alleventspages', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM eventpage');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/eventpage/:event_id', async (req, res) => {
    const event_id = parseInt(req.params.event_id, 10);
    const workgroupId = parseInt(req.query.workgroup_id, 10);

    try {
        const rows = await query(
            'SELECT * FROM eventpage WHERE event_id = $1 AND workgroup_id = $2',
            [event_id, workgroupId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Event page not found' });
        }

        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        console.error('Error querying database:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.put('/eventpage/:event_id', async (req, res) => {
    const { event_id } = req.params;
    const { workgroup_id, content } = req.body;

    // Validación de entrada
    if (!workgroup_id || !content) {
        return res.status(400).json({ message: 'workgroup_id y content son requeridos' });
    }

    try {
        // Verificar si la página existe y pertenece al workgroup
        const existingPage = await query(
            'SELECT * FROM eventpage WHERE event_id = $1 AND workgroup_id = $2',
            [event_id, workgroup_id]
        );

        // Verificar si la consulta devolvió resultados
        if (existingPage.length === 0) {
            return res.status(404).json({ message: 'Página no encontrada o no pertenece al grupo de trabajo' });
        }

        // Actualizar la página
        const updatedPage = await query(
            'UPDATE eventpage SET content = $1 WHERE event_id = $2 AND workgroup_id = $3 RETURNING *',
            [content, event_id, workgroup_id]
        );

        res.json({ message: 'Página actualizada exitosamente', data: updatedPage[0] });
    } catch (error) {
        console.error('Error al actualizar página:', error.message);
        res.status(500).json({ error: error.message });
    }
});


/***************************************************************
 * 
 *             ENPOINTS PARA PAGINA USUARIOS
 * 
 * ************************************************************/

/***************************************************************
 *                INICIO DE SESIÓN
 * ************************************************************/
app.post('/user-login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Buscar al usuario por correo electrónico
        const user = await query('SELECT * FROM Users WHERE email = $1', [email]);

        if (user.length === 0) {
            return res.status(401).json({ error: 'Correo o contraseña inválidos' });
        }

        // Verificar la contraseña
        const isMatch = await bcrypt.compare(password, user[0].password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Correo o contraseña inválidos' });
        }

        // Generar un token JWT con la información del usuario
        const token = jwt.sign(
            { id: user[0].id, email: user[0].email },
            'tu_secreto_aqui', // Cambia esto a una clave secreta segura
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Inicio de sesión exitoso',
            token,
            user_id: user[0].id,
            first_name: user[0].first_name,
            last_name: user[0].last_name,
            email: user[0].email
        });
    } catch (error) {
        res.status(500).json({ error: 'Error del servidor' });
    }
});

/***************************************************************
 *               PREFERENCIAS DEL USUARIO
 * ************************************************************/
// Endpoint para obtener las preferencias de eventos
app.get('/users/:user_id/preferences', async (req, res) => {
    const { user_id } = req.params;

    try {
        // Obtener las preferencias de eventos del usuario
        const sql = `
            SELECT user_prefs->'event_preferences' as event_preferences
            FROM public.users
            WHERE id = $1;
        `;
        const result = await query(sql, [user_id]);

        if (result.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.json({ event_preferences: result[0].event_preferences });
    } catch (error) {
        console.error('Error al obtener las preferencias:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Endpoint para guardar/actualizar las preferencias de eventos
app.put('/users/:user_id/preferences', async (req, res) => {
    const { user_id } = req.params;
    const { event_preferences } = req.body;

    if (!event_preferences) {
        return res.status(400).json({ error: 'event_preferences es requerido' });
    }

    try {
        // Actualizar las preferencias de eventos en la base de datos
        const sql = `
            UPDATE public.users
            SET user_prefs = jsonb_set(
                user_prefs,
                '{event_preferences}',
                $1::jsonb,
                true
            )
            WHERE id = $2
            RETURNING *;
        `;
        const result = await query(sql, [JSON.stringify(event_preferences), user_id]);

        if (result.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.json({ message: 'Preferencias actualizadas correctamente', user: result[0] });
    } catch (error) {
        console.error('Error al actualizar las preferencias:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

/***************************************************************
 *                   CERRAR SESIÓN GLOBAL
 * ************************************************************/
app.post('/logout', (req, res) => {
    res.clearCookie("token", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "Strict" });
    res.json({ message: "Sesión cerrada" });
});


/******************************************************************************/
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
