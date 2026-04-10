const { spawn } = require('child_process');
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
    console.log('Received registration request:', req.body,res.body);
    // We added yearLevel to the requested data
    const { username, password, role, yearLevel } = req.body;
    console.log('Parsed registration data:', { username, role, yearLevel });
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
        
        // Step 2: Check if the password matches
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        // ==============================================================
        // NEW STEP: Check if this user has a registered device
        // ==============================================================
        let registeredMacAddress = null;
        let hasDevice = false;

        // We query the devices table using the user's ID
        const [devices] = await db.query('SELECT mac_address FROM devices WHERE student_id = ?', [user.id]);
        
        if (devices.length > 0) {
            hasDevice = true;
            registeredMacAddress = devices[0].mac_address;
        }
        // ==============================================================

        // Step 3: Create a secure JWT token
        const token = jwt.sign(
            { userId: user.id, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '8h' } 
        );

        // Step 4: Add the new device info to the userData object
        const userData = {
            id: user?.id,
            username: user?.username,
            yearLevel: user?.year_level,
            role: user?.role,
            hasRegisteredDevice: hasDevice,        // NEW: true or false
            registeredMacAddress: registeredMacAddress // NEW: "AA:BB:CC..." or null
        };

        // Step 5: Send everything back to React
        res.json({ 
            message: 'Login successful!', 
            token: token, 
            role: user.role,
            user: userData
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
    // 1. Destructure the 4 new fields from the React request
    const { courseCode, courseName, yearLevel, hall, startTime, endTime, day } = req.body;
    
    // 2. Make sure the frontend sent all the necessary pieces of information
    if (!courseCode || !courseName || !yearLevel || !hall || !startTime || !endTime || !day) {
        return res.status(400).json({ error: 'All fields (course code, name, year, hall, times, and day) are required.' });
    }
    
    // Safety Check: Ensure the year level is a valid number (1, 2, 3, or 4)
    if (![1, 2, 3, 4].includes(parseInt(yearLevel))) {
        return res.status(400).json({ error: 'Year level must be 1, 2, 3, or 4.' });
    }
    
    try {
        // 3. Update the SQL query to insert all seven values
        await db.query(
            'INSERT INTO courses (course_code, course_name, year_level, hall, start_time, end_time, day) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [courseCode, courseName, yearLevel, hall, startTime, endTime, day]
        );
        
        res.status(201).json({ 
            message: `Year ${yearLevel} Course ${courseCode} created successfully!`,
            // Optional: Sending back the created course data is a great practice for the frontend
            course: { courseCode, courseName, hall, day, startTime, endTime }
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
// 12. DETAILED SESSION SUMMARY API
// ==========================================
app.get('/api/session-summary-report/:sessionId', async (req, res) => {
    const { sessionId } = req.params;

    try {
        // 1. Fetch Session Details (Adjust table/column names to match your DB)
        // Assuming you have a 'sessions' or 'lectures' table
        const [sessionRows] = await db.query(
            `SELECT id AS sessionId, course_code AS courseCode, status, start_time AS startTime 
             FROM sessions WHERE id = ?`, 
            [sessionId]
        );

        if (sessionRows.length === 0) {
            return res.status(404).json({ error: "Session not found" });
        }
        
        const sessionDetails = sessionRows[0];
        const courseCode = sessionDetails.courseCode;

        // 2. Fetch Present Students (From attendance_logs)
        const [presentStudents] = await db.query(
            `SELECT u.id AS student_id, u.username 
             FROM attendance_logs a
             JOIN users u ON a.student_id = u.id
             WHERE a.session_id = ?`,
            [sessionId]
        );

        // 3. Fetch Absent Students 
        // (Students enrolled in the course who are NOT in the attendance_logs for this session)
        const [absentStudents] = await db.query(
            `SELECT u.id AS student_id, u.username 
             FROM enrollments e
             JOIN users u ON e.student_id = u.id
             WHERE e.course_code = ? 
             AND u.id NOT IN (
                 SELECT student_id FROM attendance_logs WHERE session_id = ?
             )`,
            [courseCode, sessionId]
        );

        // 4. Calculate Summary Totals
        const presentCount = presentStudents.length;
        const absentCount = absentStudents.length;
        const totalEnrolled = presentCount + absentCount;

        // 5. Send the exact JSON structure the React frontend expects
        res.status(200).json({
            message: "Attendance report generated successfully!",
            sessionDetails: {
                sessionId: sessionDetails.sessionId,
                courseCode: sessionDetails.courseCode,
                status: sessionDetails.status,
                startTime: sessionDetails.startTime
            },
            summary: {
                totalEnrolled: totalEnrolled,
                presentCount: presentCount,
                absentCount: absentCount
            },
            data: {
                presentStudents: presentStudents,
                absentStudents: absentStudents
            }
        });

    } catch (error) {
        console.error("Detailed Report Fetch Error:", error);
        res.status(500).json({ error: "Server error while fetching detailed report." });
    }
});




// ==========================================
// 13. GET USER TIMETABLE API
// ==========================================
app.get('/api/timetable/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        // 1. First, find out who this user is (Student or Lecturer?)
        const [users] = await db.query('SELECT role, year_level FROM users WHERE id = ?', [userId]);
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }
        const user = users[0];

        let courses = [];

        // 2. Fetch the correct courses based on their role
        if (user.role === 'student') {
            // Students get courses joined from the enrollment table
            const [studentCourses] = await db.query(`
                SELECT c.course_code, c.course_name, c.hall, c.day, c.start_time, c.end_time, c.is_cancelled 
                FROM courses c
                JOIN enrollments se ON c.course_code = se.course_code
                WHERE se.student_id = ?
            `, [userId]);
            
            courses = studentCourses;
        }
        else if (user.role === 'lecturer') {
            // Lecturers get courses joined from the 'lecturer_assignment' table
            const [lecturerCourses] = await db.query(`
                SELECT c.course_code, c.course_name, c.hall, c.day, c.start_time, c.end_time, c.is_cancelled 
                FROM courses c
                JOIN lecturer_assignments la ON c.course_code = la.course_code
                WHERE la.lecturer_id = ?
            `, [userId]);
            courses = lecturerCourses;
        }

        // 3. Format the data perfectly for the React Frontend (Group by Day)
        const timetable = {
            Monday: [],
            Tuesday: [],
            Wednesday: [],
            Thursday: [],
            Friday: [],
            Saturday: [],
        };

        // Sort the courses into their specific days
        courses.forEach(course => {
            // Only add the course if the day is valid (ignores NULL or misspelled days)
            if (course.day && timetable[course.day]) {
                timetable[course.day].push(course);
            }
        });

        res.json({ timetable });

    } catch (error) {
        console.error('Timetable Error:', error);
        res.status(500).json({ error: 'Server error while fetching timetable.' });
    }
});



// ==========================================
// 14. CANCEL COURSE API (For Lecturers)
// ==========================================
app.put('/api/courses/:courseCode/cancel', async (req, res) => {
    const { courseCode } = req.params;
    const { isCancelled } = req.body; // Expects true or false

    try {
        await db.query(
            'UPDATE courses SET is_cancelled = ? WHERE course_code = ?',
            [isCancelled, courseCode]
        );
        res.json({ message: `Course ${courseCode} cancellation status updated to ${isCancelled}` });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while cancelling course.' });
    }
});

// ==========================================
// 15. FETCH STUDENT COURSES API
// ==========================================
app.get('/api/student-courses/:studentId', async (req, res) => {
    const { studentId } = req.params;

    try {
        // 1. Get the student's year level
        const [students] = await db.query('SELECT year_level FROM users WHERE id = ?', [studentId]);
        if (students.length === 0) {
            return res.status(404).json({ error: 'Student not found.' });
        }
        const studentYear = students[0].year_level;

        // 2. Fetch courses the student is ALREADY enrolled in
        const [enrolledCourses] = await db.query(
            `SELECT c.course_code, c.course_name, c.day, c.start_time, c.end_time 
             FROM enrollments e
             JOIN courses c ON e.course_code = c.course_code
             WHERE e.student_id = ?`,
            [studentId]
        );

        // 3. Fetch AVAILABLE courses (Matches year_level, but NOT already enrolled)
        const [availableCourses] = await db.query(
            `SELECT course_code, course_name, day, start_time, end_time 
             FROM courses 
             WHERE year_level = ? 
             AND course_code NOT IN (
                 SELECT course_code FROM enrollments WHERE student_id = ?
             )`,
            [studentYear, studentId]
        );

        res.status(200).json({
            enrolled: enrolledCourses,
            available: availableCourses
        });

    } catch (error) {
        console.error("Error fetching student courses:", error);
        res.status(500).json({ error: 'Server error fetching courses.' });
    }
});


// Endpoint to trigger the REAL Python Bluetooth script
app.post('/api/trigger-hardware-scan', (req, res) => {
    const { sessionId } = req.body;

    if (!sessionId) {
        return res.status(400).json({ error: "Missing sessionId" });
    }

    console.log(`🚀 Frontend requested a real scan for Session: ${sessionId}`);

    // This tells Node to run: python scanner.py <sessionId>
    const pythonProcess = spawn('python', ['scanner.py', sessionId]);

    // This grabs any print() statements from Python and shows them in the Node terminal
    pythonProcess.stdout.on('data', (data) => {
        console.log(`🐍 Python: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`❌ Python Error: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`🛑 Python scanner finished. (Code ${code})`);
    });

    res.json({ message: "Hardware scan started successfully!" });
});




// ==========================================
// 13. GET LECTURER COURSE ASSIGNMENTS API
// ==========================================
app.get('/api/lecturer/:lecturerId/courses', async (req, res) => {
    const { lecturerId } = req.params;

    try {
        // 1. Get Assigned Courses (Using the junction table)
        const [assignedRaw] = await db.query(`
            SELECT c.course_code, c.course_name, c.year_level 
            FROM courses c
            JOIN lecturer_assignments la ON c.course_code = la.course_code
            WHERE la.lecturer_id = ?
        `, [lecturerId]);

        // 2. Get Available Courses (Courses NOT assigned to this lecturer)
        const [availableRaw] = await db.query(`
            SELECT course_code, course_name, year_level 
            FROM courses
            WHERE course_code NOT IN (
                SELECT course_code FROM lecturer_assignments WHERE lecturer_id = ?
            )
        `, [lecturerId]);

        // 3. Helper function to group the courses by Year Level (1, 2, 3, 4)
        // This makes the React frontend's job incredibly easy!
        const formatByYear = (coursesArray) => {
            const grouped = { 1: [], 2: [], 3: [], 4: [] };
            coursesArray.forEach(course => {
                // Ensure the year level is valid before pushing
                if (grouped[course.year_level]) {
                    grouped[course.year_level].push({ 
                        code: course.course_code, 
                        name: course.course_name 
                    });
                }
            });
            return grouped;
        };

        // 4. Send the perfectly formatted package back to React
        res.json({
            assigned: formatByYear(assignedRaw),
            available: formatByYear(availableRaw)
        });

    } catch (error) {
        console.error('Error fetching lecturer courses:', error);
        res.status(500).json({ error: 'Server error while fetching courses.' });
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