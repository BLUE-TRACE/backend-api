const express = require('express');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db'); 

const app = express();


app.use(cors());
app.use(express.json());

// A simple test route to make sure the server is alive
app.get('/', (req, res) => {
    res.send('BlueTrace Backend Server is Running!');
});

// Turn on the server and test the database connection
const PORT = process.env.PORT || 5000;



// ==========================================
// 1. USER REGISTRATION API
// ==========================================
app.post('/api/register', async (req, res) => {
    // We added yearLevel to the requested data
    const { username, password, role, yearLevel } = req.body;
    try {
        // Safety check: If they are a student, they MUST provide a year level
        if (role === 'student' && !yearLevel) {
            return res.status(400).json({ error: 'Students must provide a year level (1, 2, 3, or 4).' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        // Insert the user. If they aren't a student, year_level just stays NULL.
        const [result] = await db.query(
            'INSERT INTO users (username, password, role, year_level) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, role === 'student' ? yearLevel : null]
        );
        res.status(201).json({ 
            message: 'User registered successfully!', 
            userId: result.insertId 
        });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Username already exists.' });
        }
        console.error(error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});




// ==========================================
// 2. USER LOGIN API
// ==========================================
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        // Step 1: Find the user in the database
        const [users] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }
        const user = users[0];
        // Step 2: Check if the password matches the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }
        // Step 3: Create a secure JWT token (the "digital key")
        const token = jwt.sign(
            { userId: user.id, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '8h' } // Token expires in 8 hours
        );
        // Step 4: Send the token and user role back to the React web app
        res.json({ 
            message: 'Login successful!', 
            token: token, 
            role: user.role 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error during login.' });
    }
});



// ==========================================
// 3. DEVICE REGISTRATION API
// ==========================================
app.post('/api/register-device', async (req, res) => {
    // The web app will send the student's ID and their phone's MAC address
    const { studentId, macAddress } = req.body;
    try {
        // Insert the MAC address into the database. 
        // If the student_id already exists, update their old MAC address with the new one.
        const [result] = await db.query(
            `INSERT INTO devices (student_id, mac_address) 
             VALUES (?, ?) 
             ON DUPLICATE KEY UPDATE mac_address = ?`,
            [studentId, macAddress, macAddress]
        );
        res.status(200).json({ 
            message: 'Device registered successfully!',
            macAddress: macAddress
        });
    } catch (error) {
        // If the MAC address is exactly the same as another student's (fraud)
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ 
                error: 'This MAC address is already registered to another user.' 
            });
        }
        console.error(error);
        res.status(500).json({ error: 'Server error during device registration.' });
    }
});




// ==========================================
// 4. START LECTURE SESSION API (Secured)
// ==========================================
app.post('/api/start-session', async (req, res) => {
    // The React web app sends the Course Code and the Lecturer's ID
    const { courseCode, lecturerId } = req.body;

    if (!courseCode || !lecturerId) {
        return res.status(400).json({ error: 'Course Code and Lecturer ID are required.' });
    }

    try {
        // --- NEW SECURITY CHECK ---
        // Verify that this specific lecturer is actually assigned to teach this course
        const [assignment] = await db.query(
            'SELECT * FROM lecturer_assignments WHERE lecturer_id = ? AND course_code = ?',
            [lecturerId, courseCode]
        );

        if (assignment.length === 0) {
            return res.status(403).json({ 
                error: `Access Denied: Lecturer ${lecturerId} is not assigned to teach ${courseCode}.` 
            });
        }
        // --------------------------

        // If they pass the check, create the active session
        const [result] = await db.query(
            `INSERT INTO sessions (course_code, lecturer_id, status) 
             VALUES (?, ?, 'active')`,
            [courseCode, lecturerId]
        );

        res.status(201).json({ 
            message: `Lecture session for ${courseCode} started successfully!`,
            sessionId: result.insertId 
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while starting the session.' });
    }
});




// ==========================================
// 5. STOP LECTURE SESSION API
// ==========================================
app.post('/api/stop-session', async (req, res) => {
    // The React web app sends the specific Session ID to close it
    const { sessionId } = req.body;

    try {
        // Update the session status in the database to 'closed'
        const [result] = await db.query(
            `UPDATE sessions SET status = 'closed' WHERE id = ?`,
            [sessionId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Session not found.' });
        }

        res.status(200).json({ message: 'Lecture session closed successfully!' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while stopping the session.' });
    }
});




// ==========================================
// 6. BLUETOOTH SCAN INGESTION API (For Python)
// ==========================================
app.post('/api/scan', async (req, res) => {
    // The Python script sends the active Session ID and a list of MAC addresses
    const { sessionId, macAddresses } = req.body;

    // Safety check: Make sure the Python script actually sent data
    if (!sessionId || !macAddresses || macAddresses.length === 0) {
        return res.status(400).json({ error: 'Missing session ID or MAC addresses.' });
    }

    try {
        // Step 1: Double-check that this lecture session is still "active"
        const [sessions] = await db.query(
            'SELECT * FROM sessions WHERE id = ? AND status = "active"', 
            [sessionId]
        );

        if (sessions.length === 0) {
            return res.status(400).json({ error: 'Session is closed or does not exist.' });
        }

        // Step 2: Look up registered devices, BUT only allow students enrolled in this specific course
        // This prevents the scanner from picking up students in the classroom next door!
        const [devices] = await db.query(
            `SELECT d.student_id 
             FROM devices d
             JOIN enrollments e ON d.student_id = e.student_id
             JOIN sessions s ON e.course_code = s.course_code
             WHERE d.mac_address IN (?) AND s.id = ?`,
            [macAddresses, sessionId]
        );

        if (devices.length === 0) {
            return res.status(200).json({ 
                message: 'No enrolled student devices found in this scan.',
                totalDevicesFound: 0,
                newStudentsMarked: 0
            });
        }

        // Step 3: Prepare the attendance data to be saved
        // This creates a format like: [[session_id, student_1, 'present'], [session_id, student_2, 'present']]
        const attendanceRecords = devices.map(device => [sessionId, device.student_id, 'present']);

        // Step 4: Save them as "Present" in the database!
        const [result] = await db.query(
            'INSERT IGNORE INTO attendance_logs (session_id, student_id, status) VALUES ?',
            [attendanceRecords]
        );

        res.status(200).json({ 
            message: 'Scan processed successfully!',
            totalDevicesFound: devices.length,
            newStudentsMarked: result.affectedRows // Shows '0' if they were already marked present in a previous scan
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while processing the Bluetooth scan.' });
    }
});



// ==========================================
// 7. LIVE DASHBOARD API (For React Web App)
// ==========================================
app.get('/api/live-attendance/:sessionId', async (req, res) => {
    // We grab the session ID directly from the URL (e.g., /api/live-attendance/1)
    const { sessionId } = req.params;

    try {
        // We use a SQL JOIN to combine the attendance_logs table with the users table.
        // This way, React gets the actual student names, not just their ID numbers.
        const [attendanceData] = await db.query(
            `SELECT u.username, u.id AS student_id, a.timestamp, a.status 
             FROM attendance_logs a
             JOIN users u ON a.student_id = u.id
             WHERE a.session_id = ?
             ORDER BY a.timestamp DESC`,
            [sessionId]
        );

        res.status(200).json({
            message: 'Live attendance fetched successfully!',
            totalPresent: attendanceData.length,
            students: attendanceData
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while fetching live attendance.' });
    }
});



// ==========================================
// 8. ATTENDANCE REPORTING API (For React Web App)
// ==========================================
app.get('/api/reports/attendance', async (req, res) => {
    // The web app asks for a report for a specific course
    const { courseCode } = req.query;

    if (!courseCode) {
        return res.status(400).json({ error: 'Course code is required to generate a report.' });
    }

    try {
        // We use a complex SQL query to join 3 tables: Sessions, Attendance_Logs, and Users.
        // This builds a complete historical timeline of who attended which lecture.
        const query = `
            SELECT 
                s.start_time AS session_date,
                u.username AS student_name,
                u.id AS student_id,
                a.status,
                a.timestamp AS marked_at
            FROM sessions s
            JOIN attendance_logs a ON s.id = a.session_id
            JOIN users u ON a.student_id = u.id
            WHERE s.course_code = ?
            ORDER BY s.start_time DESC, u.username ASC
        `;

        const [reportData] = await db.query(query, [courseCode]);

        res.status(200).json({
            message: 'Attendance report generated successfully!',
            totalRecords: reportData.length,
            report: reportData
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while generating the report.' });
    }
});




// ==========================================
// 9. CREATE COURSE API (Administrative)
// ==========================================
app.post('/api/courses', async (req, res) => {
    // We added yearLevel to the requested data
    const { courseCode, courseName, yearLevel } = req.body;

    // Make sure the frontend sent all three pieces of information
    if (!courseCode || !courseName || !yearLevel) {
        return res.status(400).json({ error: 'Course code, name, and year level are required.' });
    }

    // Safety Check: Ensure the year level is a valid number (1, 2, 3, or 4)
    if (![1, 2, 3, 4].includes(parseInt(yearLevel))) {
        return res.status(400).json({ error: 'Year level must be 1, 2, 3, or 4.' });
    }

    try {
        // Update the SQL query to insert all three values
        await db.query(
            'INSERT INTO courses (course_code, course_name, year_level) VALUES (?, ?, ?)',
            [courseCode, courseName, yearLevel]
        );

        res.status(201).json({ 
            message: `Year ${yearLevel} Course ${courseCode} created successfully!` 
        });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'This course code already exists.' });
        }
        console.error(error);
        res.status(500).json({ error: 'Server error while creating the course.' });
    }
});





// ==========================================
// 10. ASSIGN LECTURER TO COURSE API 
// ==========================================
app.post('/api/assign-lecturer', async (req, res) => {
    // The frontend sends the Lecturer's user ID and the Course Code
    const { lecturerId, courseCode } = req.body;

    if (!lecturerId || !courseCode) {
        return res.status(400).json({ error: 'Lecturer ID and Course Code are required.' });
    }

    try {
        await db.query(
            'INSERT INTO lecturer_assignments (lecturer_id, course_code) VALUES (?, ?)',
            [lecturerId, courseCode]
        );

        res.status(200).json({ 
            message: `Lecturer ${lecturerId} is now assigned to teach ${courseCode}!` 
        });

    } catch (error) {
        // If they try to assign the same lecturer to the same course twice
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'This lecturer is already assigned to this course.' });
        }
        // If they type a fake course code or fake lecturer ID
        if (error.code === 'ER_NO_REFERENCED_ROW_2') {
            return res.status(400).json({ error: 'Invalid Lecturer ID or Course Code. Ensure both exist.' });
        }
        console.error(error);
        res.status(500).json({ error: 'Server error while assigning the lecturer.' });
    }
});




// ==========================================
// 11. STUDENT ENROLLMENT API
// ==========================================
app.post('/api/enroll', async (req, res) => {
    // The frontend sends the Student's ID and the Course Code they want to join
    const { studentId, courseCode } = req.body;

    if (!studentId || !courseCode) {
        return res.status(400).json({ error: 'Student ID and Course Code are required.' });
    }

    try {
        // Step 1: Look up the student to see what year they are in
        const [students] = await db.query('SELECT role, year_level FROM users WHERE id = ?', [studentId]);
        
        if (students.length === 0 || students[0].role !== 'student') {
            return res.status(400).json({ error: 'Invalid Student ID.' });
        }
        const studentYear = students[0].year_level;

        // Step 2: Look up the course to see what year it is for
        const [courses] = await db.query('SELECT year_level FROM courses WHERE course_code = ?', [courseCode]);
        
        if (courses.length === 0) {
            return res.status(404).json({ error: 'Course not found.' });
        }
        const courseYear = courses[0].year_level;

        // Step 3: THE SECURITY CHECK! Compare the years.
        if (studentYear !== courseYear) {
            return res.status(403).json({ 
                error: `Enrollment denied. This is a Year ${courseYear} course, but you are a Year ${studentYear} student.` 
            });
        }

        // Step 4: If they pass the check, officially enroll them in the database
        await db.query(
            'INSERT INTO enrollments (student_id, course_code) VALUES (?, ?)',
            [studentId, courseCode]
        );

        res.status(200).json({ message: `Successfully enrolled in ${courseCode}!` });

    } catch (error) {
        // Stop them from enrolling in the same course twice
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'You are already enrolled in this course.' });
        }
        console.error(error);
        res.status(500).json({ error: 'Server error during enrollment.' });
    }
});




// ==========================================
// 12. SESSION ATTENDANCE REPORT API
// ==========================================
app.get('/api/reports/session/:sessionId', async (req, res) => {
    // We get the specific session ID from the URL
    const { sessionId } = req.params;

    try {
        // Step 1: Find the session to see which course it belongs to
        const [sessions] = await db.query(
            'SELECT course_code, start_time, status FROM sessions WHERE id = ?', 
            [sessionId]
        );
        
        if (sessions.length === 0) {
            return res.status(404).json({ error: 'Session not found.' });
        }
        
        const sessionData = sessions[0];
        const courseCode = sessionData.course_code;

        // Step 2: Get EVERY student officially enrolled in this course
        const [enrolledStudents] = await db.query(
            `SELECT u.id AS student_id, u.username 
             FROM enrollments e 
             JOIN users u ON e.student_id = u.id 
             WHERE e.course_code = ?`,
            [courseCode]
        );

        // Step 3: Get ONLY the students who were marked PRESENT by the Bluetooth scanner
        const [presentRecords] = await db.query(
            `SELECT student_id 
             FROM attendance_logs 
             WHERE session_id = ? AND status = 'present'`,
            [sessionId]
        );

        // Step 4: The Math Engine - Calculate who is missing
        // First, extract just the ID numbers of the present students into a simple list
        const presentStudentIds = presentRecords.map(record => record.student_id);

        // Filter the master enrollment list into two separate groups
        const presentList = enrolledStudents.filter(student => presentStudentIds.includes(student.student_id));
        const absentList = enrolledStudents.filter(student => !presentStudentIds.includes(student.student_id));

        // Step 5: Send the beautiful, structured report back to the frontend
        res.status(200).json({
            message: 'Attendance report generated successfully!',
            sessionDetails: {
                sessionId: parseInt(sessionId),
                courseCode: courseCode,
                status: sessionData.status,
                startTime: sessionData.start_time
            },
            summary: {
                totalEnrolled: enrolledStudents.length,
                presentCount: presentList.length,
                absentCount: absentList.length
            },
            data: {
                presentStudents: presentList,
                absentStudents: absentList
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while generating the attendance report.' });
    }
});




app.listen(PORT, async () => {
    console.log(`🚀 Server is running on port ${PORT}`);
    
    try {
        // Test the database connection
        const [rows] = await db.query('SELECT 1 + 1 AS solution');
        console.log('✅ Successfully connected to the MySQL Database!');
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
    }
});