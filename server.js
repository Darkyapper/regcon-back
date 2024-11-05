const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); 

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

// Configuración de Multer para carga de archivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ storage });

app.use(cors({
    origin: '*', // Permitir todas las solicitudes de origen
}));

app.use(express.json());

// Configuración de conexión a Supabase PostgreSQL
const pool = new Pool({
    host: 'aws-0-us-west-1.pooler.supabase.com',
    user: 'postgres.vfwkmxsgdsnpdtebeize',
    password: 'R4dI@-JKdaNCE',
    database: 'postgres',
    port: 6543,
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

const generateTempPassword = () => {
    const length = 12;
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let tempPassword = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        tempPassword += charset[randomIndex];
    }
    return tempPassword;
};

/***************************************************************
 * 
 *                ENPOINTS PARA ADMINISTRADORES
 * 
 * ************************************************************/
// Enpoints para usuarios
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
    const { first_name, last_name, email, phone } = req.body;
    
    // Generar una contraseña temporal
    const tempPassword = generateTempPassword(); 
    // Encriptar la contraseña antes de guardarla
    const hashedPassword = await bcrypt.hash(tempPassword, saltRounds);
    
    try {
        const rows = await query(
            'INSERT INTO Users (first_name, last_name, email, phone, password) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [first_name, last_name, email, phone, hashedPassword]
        );
        res.json({ message: 'Usuario registrado exitosamente. La contraseña temporal es: ' + tempPassword, data: rows[0] });
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

// Endpoints para Eventos
app.post('/events', async (req, res) => {
    const { name, event_date, location, description, category_id, workgroup_id, image } = req.body;
    try {
        const rows = await query(
            'INSERT INTO Events (name, event_date, location, description, category_id, workgroup_id, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [name, event_date, location, description, category_id, workgroup_id, image]
        );
        res.json({ message: 'Event created successfully', data: rows[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/events', async (req, res) => {
    const { workgroup_id } = req.query; // Obtén el workgroup_id de la consulta

    try {
        const rows = await query('SELECT * FROM Events WHERE workgroup_id = $1', [workgroup_id]);
        res.json({ message: 'Success', data: rows });
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
    const { name, event_date, location, description, category_id, workgroup_id } = req.body;
    const { id } = req.params;
    try {
        const rows = await query(
            `UPDATE Events SET name = $1, event_date = $2, location = $3, description = $4, category_id = $5, workgroup_id = $6 WHERE id = $7 RETURNING *`,
            [name, event_date, location, description, category_id, workgroup_id, id]
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

// Endpoints para TicketCategories
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


// Endpoints para boletos
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


// Endpoint para tener los boletos con su información completa
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



// Endpoints para registros (Attendance en lugar de Registration)
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

// Endpoint para obtener los registros con información completa (AttendanceDetails en lugar de RegistrationDetails)
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

// enpoint para obtener las categorías de boletos con sus respectivos conteos
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

// Obtener todos los boletos de una categoría específica
app.get('/tickets/category/:category_id', async (req, res) => {
    const { category_id } = req.params;
    try {
        const rows = await query('SELECT * FROM Tickets WHERE category_id = $1', [category_id]);
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Endpoints para grupos de trabajo
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

// Endpoints para administradores
app.get('/admin', async (req, res) => {
    try {
        const rows = await query('SELECT * FROM Admin');
        res.json({ message: 'Success', data: rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/admin/:id', async (req, res) => {
    const { id } = req.params;
    const workgroupId = req.query.workgroup_id; // Obtener el workgroup_id de la consulta

    try {
        const rows = await query('SELECT * FROM Admin WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Admin not found' });

        // Verificar si el admin pertenece al workgroup actual
        const membershipCheck = await query('SELECT * FROM membership WHERE admin_id = $1 AND workgroup_id = $2', [id, workgroupId]);
        if (membershipCheck.length === 0) {
            return res.status(403).json({ message: 'Este administrador no pertenece al grupo de trabajo actual.' });
        }

        res.json({ message: 'Success', data: rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
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

// Endpoints para roles
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

// Endpoint para iniciar sesión
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Buscar al administrador por correo electrónico
        const admin = await query('SELECT * FROM Admin WHERE email = $1', [email]);

        if (admin.length === 0) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        // Verificar la contraseña
        const isMatch = await bcrypt.compare(password, admin[0].password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        // Obtener el workgroup_id de la tabla membership
        const membership = await query('SELECT workgroup_id, role_id FROM membership WHERE admin_id = $1', [admin[0].id]);
        const workgroup_id = membership.length > 0 ? membership[0].workgroup_id : null;
        const role_id = membership.length > 0 ? membership[0].role_id : null; // Obtener role_id

        // Crear un token
        const token = jwt.sign({ id: admin[0].id, workgroup_id, role_id }, 'tu_secreto_aqui', { expiresIn: '1h' });

        res.json({ message: 'Inicio de sesión exitoso', token, workgroup_id, role_id, user_id: admin[0].id }); // Agregar role_id aquí
    } catch (error) {
        res.status(500).json({ error: 'Error del servidor' });
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

// Obtener registros de la vista eventattendancesummary
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
 * 
 *             ENPOINTS PARA PAGINA USUARIOS
 * 
 * ************************************************************/

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
