const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { body } = require('express-validator');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
require('dotenv').config();

const { Teacher, Student, Class, Attendance, Session, Request, Holiday } = require('./models');
const { authenticate, authorize, handleValidation, auditLog, errorHandler } = require('./middleware');
const { AttendanceService, NotificationService, ReportService } = require('./services');

const app = express();

// Middleware
app.use(helmet());
app.use(compression());
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:5173",
      "http://10.34.7.43:3000",
      "capacitor://localhost",
      "http://localhost",
      'https://smart-attendance-backend-cadt.onrender.com'// For Capacitor
    ],
    credentials: true,
  })
);
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});
app.use('/api/', limiter);

// Auth rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// ===================== AUTH ROUTES =====================

// Teacher Login
app.post('/api/auth/teacher/login', 
  authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
  ], 
  handleValidation,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      
      const teacher = await Teacher.findOne({ email });
      if (!teacher || !(await teacher.comparePassword(password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { id: teacher._id, type: 'teacher', role: teacher.role },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        token,
        user: {
          id: teacher._id,
          name: teacher.name,
          email: teacher.email,
          role: teacher.role
        }
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// Student Login
app.post('/api/auth/student/login',
  authLimiter,
  [
    body('rollNumber').isLength({ min: 12, max: 12 }),
    body('pin').isLength({ min: 4, max: 4 }),
    body('deviceId').notEmpty()
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { rollNumber, pin, deviceId, deviceInfo } = req.body;
      
      const student = await Student.findOne({ rollNumber });
      if (!student || !(await student.comparePin(pin))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Device binding check
      if (student.deviceId && student.deviceId !== deviceId) {
        return res.status(403).json({ error: 'This account is registered on another device' });
      }

      // First login - bind device
      if (!student.deviceId) {
        student.deviceId = deviceId;
        student.deviceInfo = deviceInfo;
        await student.save();
      }

      const token = jwt.sign(
        { id: student._id, type: 'student' },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
      );

      res.json({
        token,
        user: {
          id: student._id,
          name: student.name,
          rollNumber: student.rollNumber,
          classId: student.classId
        }
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// Student Registration
app.post('/api/auth/student/register',
  [
    body('name').notEmpty().trim(),
    body('rollNumber').isLength({ min: 12, max: 12 }),
    body('pin').isLength({ min: 4, max: 4 }).isNumeric()
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, rollNumber, pin } = req.body;
      
      // Check if student exists
      const existing = await Student.findOne({ rollNumber });
      if (existing) {
        return res.status(400).json({ error: 'Roll number already registered' });
      }

      // Find class based on roll number pattern (customize as needed)
      const classCode = rollNumber.substring(0, 6);
      const classDoc = await Class.findOne({ 
        name: { $regex: classCode, $options: 'i' } 
      });

      if (!classDoc) {
        return res.status(400).json({ error: 'Invalid roll number. Class not found.' });
      }

      const student = await Student.create({
        name,
        rollNumber,
        pin,
        classId: classDoc._id
      });

      res.status(201).json({ 
        message: 'Registration successful. Please login with your device.' 
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// Update FCM Token
app.put('/api/auth/fcm-token',
  authenticate,
  [body('fcmToken').notEmpty()],
  handleValidation,
  async (req, res) => {
    try {
      const { fcmToken } = req.body;
      
      if (req.userType === 'teacher') {
        await Teacher.findByIdAndUpdate(req.user._id, { fcmToken });
      } else {
        await Student.findByIdAndUpdate(req.user._id, { fcmToken });
      }

      res.json({ message: 'FCM token updated' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// ===================== CLASS MANAGEMENT (CC Only) =====================

// Create Class
app.post('/api/classes',
  authenticate,
  authorize(['CC']),
  auditLog('CREATE_CLASS'),
  [
    body('name').notEmpty(),
    body('section').notEmpty(),
    body('year').isInt({ min: 1, max: 4 })
  ],
  handleValidation,
  async (req, res) => {
    try {
      const classDoc = await Class.create({
        ...req.body,
        createdBy: req.user._id
      });

      res.status(201).json(classDoc);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// Get All Classes
app.get('/api/classes',
  authenticate,
  async (req, res) => {
    try {
      let query = {};
      
      // Staff can only see assigned classes
      if (req.userType === 'teacher' && req.user.role === 'STAFF') {
        const assignedClassIds = req.user.assignedPeriods.map(p => p.classId);
        query._id = { $in: assignedClassIds };
      }

      const classes = await Class.find(query)
        .populate('createdBy', 'name email')
        .sort('name section');

      res.json(classes);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// Update Class Timetable
app.put('/api/classes/:id/timetable',
  authenticate,
  authorize(['CC']),
  auditLog('UPDATE_TIMETABLE'),
  async (req, res) => {
    try {
      const { timetable } = req.body;
      
      const classDoc = await Class.findByIdAndUpdate(
        req.params.id,
        { timetable },
        { new: true }
      );

      // Update teacher assignments
      for (const day of Object.keys(timetable)) {
        for (const period of timetable[day]) {
          if (period.staffId) {
            await Teacher.findByIdAndUpdate(
              period.staffId,
              {
                $addToSet: {
                  assignedPeriods: {
                    classId: classDoc._id,
                    period: period.period
                  }
                }
              }
            );
          }
        }
      }

      // Notify students about timetable change
      await NotificationService.notifyClassStudents(
        classDoc._id,
        'Timetable Updated',
        'Your class timetable has been updated. Please check the app.'
      );

      res.json(classDoc);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// ===================== STUDENT MANAGEMENT (CC Only) =====================

// Add Student to Class
app.post('/api/students',
  authenticate,
  authorize(['CC']),
  auditLog('ADD_STUDENT'),
  [
    body('name').notEmpty(),
    body('rollNumber').isLength({ min: 12, max: 12 }),
    body('classId').isMongoId()
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, rollNumber, classId } = req.body;
      
      // Generate random PIN
      const pin = Math.floor(1000 + Math.random() * 9000).toString();
      
      const student = await Student.create({
        name,
        rollNumber,
        pin,
        classId
      });

      res.status(201).json({
        message: 'Student added successfully',
        student: {
          name: student.name,
          rollNumber: student.rollNumber,
          pin // Show PIN only on creation
        }
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// Get Students by Class
app.get('/api/classes/:classId/students',
  authenticate,
  async (req, res) => {
    try {
      const students = await Student.find({ 
        classId: req.params.classId,
        isActive: true 
      })
      .select('-pin')
      .sort('rollNumber');

      res.json(students);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// ===================== ATTENDANCE ROUTES =====================

// Start Attendance Session (Teacher)
app.post('/api/attendance/session/start',
  authenticate,
  authorize(['CC', 'STAFF']),
  auditLog('START_ATTENDANCE'),
  [
    body('classId').isMongoId(),
    body('period').isInt({ min: 1, max: 8 }),
    body('mode').isIn(['BLE', 'WIFI', 'INTERNET'])
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { classId, period, mode } = req.body;
      
      // Check if holiday
      const holidayStatus = await AttendanceService.isHoliday(new Date());
      if (holidayStatus.isHoliday) {
        return res.status(400).json({ 
          error: `Cannot take attendance on ${holidayStatus.reason}` 
        });
      }

      // Check if session already exists
      const existingSession = await Session.findOne({
        classId,
        date: new Date().setHours(0,0,0,0),
        period,
        isActive: true
      });

      if (existingSession) {
        return res.status(400).json({ error: 'Session already active for this period' });
      }

      // Create session
      const session = await AttendanceService.createSession(
        classId,
        req.user._id,
        period,
        mode
      );

      res.json({
        sessionId: session._id,
        mode: session.mode,
        token: session.token,
        code: session.code,
        ssid: session.ssid,
        expiresAt: session.expiresAt
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
});

// Mark Attendance (Student)
app.post(
  "/api/attendance/mark",
  authenticate,
  [
    body("sessionId").isMongoId(),
    body("token").notEmpty(),
    body("location").optional().isObject(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { sessionId, token, location } = req.body;
      const deviceId = req.header("X-Device-Id");

      // Verify session and token
      const session = await Session.findById(sessionId);
      if (!session || session.token !== token) {
        return res.status(400).json({ error: "Invalid session or token" });
      }

      // Mark attendance
      const attendance = await AttendanceService.markAttendance(
        sessionId,
        req.user._id,
        deviceId,
        location
      );

      res.json({
        message: "Attendance marked successfully",
        attendance,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Campus Attendance (Student)
app.post(
  "/api/attendance/campus",
  authenticate,
  [body("location.latitude").isFloat(), body("location.longitude").isFloat()],
  handleValidation,
  async (req, res) => {
    try {
      const { location } = req.body;
      const deviceId = req.header("X-Device-Id");

      const attendance = await AttendanceService.markCampusAttendance(
        req.user._id,
        location,
        deviceId
      );

      res.json({
        message: "Campus attendance marked successfully",
        attendance,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Get Attendance Status (Student)
app.get("/api/attendance/status", authenticate, async (req, res) => {
  try {
    const today = new Date().setHours(0, 0, 0, 0);

    // Campus attendance
    const campusAttendance = await Attendance.findOne({
      studentId: req.user._id,
      date: today,
      type: "CAMPUS",
    });

    // Class attendance for all periods
    const classAttendance = await Attendance.find({
      studentId: req.user._id,
      date: today,
      type: "CLASS",
    }).sort("period");

    // Active sessions for student's class
    const activeSessions = await Session.find({
      classId: req.user.classId,
      date: today,
      isActive: true,
      expiresAt: { $gt: new Date() },
    }).select("period mode code ssid expiresAt");

    res.json({
      campus: campusAttendance,
      classes: classAttendance,
      activeSessions,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===================== REQUESTS =====================

// Submit Request (Student)
app.post(
  "/api/requests",
  authenticate,
  auditLog("SUBMIT_REQUEST"),
  [
    body("type").isIn(["MANUAL_ATTENDANCE", "FRIEND_ATTENDANCE"]),
    body("date").isISO8601(),
    body("reason").notEmpty().isLength({ min: 10, max: 500 }),
    body("period").optional().isInt({ min: 1, max: 8 }),
    body("friendRollNumber").optional().isLength({ min: 12, max: 12 }),
  ],
  handleValidation,
  async (req, res) => {
    try {
      if (req.userType !== "student") {
        return res.status(403).json({ error: "Students only" });
      }

      const request = await Request.create({
        studentId: req.user._id,
        ...req.body,
      });

      // Notify teachers
      const student = await Student.findById(req.user._id).populate("classId");
      const teachers = await Teacher.find({
        $or: [
          { role: "CC" },
          { "assignedPeriods.classId": student.classId._id },
        ],
      });

      for (const teacher of teachers) {
        await NotificationService.notifyUser(
          teacher._id,
          "teacher",
          "New Attendance Request",
          `${student.name} has submitted an attendance request`
        );
      }

      res.status(201).json(request);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Get Requests (Teacher)
app.get(
  "/api/requests",
  authenticate,
  authorize(["CC", "STAFF"]),
  async (req, res) => {
    try {
      const { status, type } = req.query;
      const query = {};

      if (status) query.status = status;
      if (type) query.type = type;

      // If staff, only show requests for their classes
      if (req.user.role === "STAFF") {
        const classIds = req.user.assignedPeriods.map((p) => p.classId);
        const students = await Student.find({ classId: { $in: classIds } });
        query.studentId = { $in: students.map((s) => s._id) };
      }

      const requests = await Request.find(query)
        .populate("studentId", "name rollNumber")
        .populate("reviewedBy", "name")
        .sort("-createdAt");

      res.json(requests);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Review Request (Teacher)
app.put(
  "/api/requests/:id/review",
  authenticate,
  authorize(["CC", "STAFF"]),
  auditLog("REVIEW_REQUEST"),
  [
    body("status").isIn(["APPROVED", "REJECTED"]),
    body("reviewNote").optional().isString(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { status, reviewNote } = req.body;

      const request = await Request.findByIdAndUpdate(
        req.params.id,
        {
          status,
          reviewNote,
          reviewedBy: req.user._id,
        },
        { new: true }
      ).populate("studentId");

      // If approved, create attendance record
      if (status === "APPROVED" && request.type === "MANUAL_ATTENDANCE") {
        await Attendance.create({
          studentId: request.studentId._id,
          classId: request.studentId.classId,
          date: request.date,
          type: request.period ? "CLASS" : "CAMPUS",
          period: request.period,
          status: "PRESENT",
          mode: "MANUAL",
          markedBy: req.user._id,
          reason: request.reason,
        });
      }

      // Notify student
      await NotificationService.notifyUser(
        request.studentId._id,
        "student",
        "Request " + status,
        `Your attendance request has been ${status.toLowerCase()}`
      );

      res.json(request);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Submit Absence Reason (Student)
app.post(
  "/api/attendance/absence-reason",
  authenticate,
  [
    body("date").isISO8601(),
    body("reason").notEmpty().isLength({ min: 10, max: 500 }),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { date, reason } = req.body;

      // Update all absent records for the date
      await Attendance.updateMany(
        {
          studentId: req.user._id,
          date: new Date(date).setHours(0, 0, 0, 0),
          status: "ABSENT",
        },
        { reason }
      );

      res.json({ message: "Absence reason submitted" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// ===================== HOLIDAYS (CC Only) =====================

// Create Holiday
app.post(
  "/api/holidays",
  authenticate,
  authorize(["CC"]),
  auditLog("CREATE_HOLIDAY"),
  [
    body("name").notEmpty(),
    body("startDate").isISO8601(),
    body("endDate").isISO8601(),
    body("type").isIn(["SPECIAL", "SATURDAY_WORKING"]),
    body("mappedDay")
      .optional()
      .isIn(["monday", "tuesday", "wednesday", "thursday", "friday"]),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const holiday = await Holiday.create({
        ...req.body,
        createdBy: req.user._id,
      });

      // Notify all users
      const students = await Student.find({ fcmToken: { $exists: true } });
      const teachers = await Teacher.find({ fcmToken: { $exists: true } });

      const message =
        holiday.type === "SPECIAL"
          ? `Holiday declared: ${holiday.name}`
          : `Saturday working day: ${new Date(
              holiday.startDate
            ).toDateString()}`;

      const notifications = [
        ...students.map((s) =>
          NotificationService.notifyUser(
            s._id,
            "student",
            "Holiday Update",
            message
          )
        ),
        ...teachers.map((t) =>
          NotificationService.notifyUser(
            t._id,
            "teacher",
            "Holiday Update",
            message
          )
        ),
      ];

      await Promise.all(notifications);

      res.status(201).json(holiday);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Get Holidays
app.get("/api/holidays", authenticate, async (req, res) => {
  try {
    const holidays = await Holiday.find()
      .populate("createdBy", "name")
      .sort("-startDate");

    res.json(holidays);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===================== REPORTS =====================

// Get Attendance Report
app.get("/api/reports/attendance", authenticate, async (req, res) => {
  try {
    const { classId, startDate, endDate, format = "json" } = req.query;

    // Validate permissions
    if (req.userType === "student") {
      return res.status(403).json({ error: "Access denied" });
    }

    if (req.user.role === "STAFF") {
      const hasAccess = req.user.assignedPeriods.some(
        (p) => p.classId.toString() === classId
      );
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied to this class" });
      }
    }

    const report = await ReportService.generateAttendanceReport(
      classId,
      new Date(startDate),
      new Date(endDate),
      format
    );

    if (format === "csv") {
      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        "attachment; filename=attendance-report.csv"
      );
      res.send(report);
    } else if (format === "pdf") {
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        "attachment; filename=attendance-report.pdf"
      );
      res.send(report);
    } else {
      res.json(report);
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Student Attendance Summary
app.get("/api/reports/student/:studentId", authenticate, async (req, res) => {
  try {
    const studentId = req.params.studentId;

    // Students can only view their own report
    if (req.userType === "student" && req.user._id.toString() !== studentId) {
      return res.status(403).json({ error: "Access denied" });
    }

    const student = await Student.findById(studentId);
    if (!student) {
      return res.status(404).json({ error: "Student not found" });
    }

    const attendances = await Attendance.find({ studentId }).sort("-date");

    const summary = {
      total: attendances.length,
      present: attendances.filter((a) => a.status === "PRESENT").length,
      absent: attendances.filter((a) => a.status === "ABSENT").length,
      percentage: 0,
      records: attendances,
    };

    if (summary.total > 0) {
      summary.percentage = Math.round((summary.present / summary.total) * 100);
    }

    res.json(summary);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===================== STAFF MANAGEMENT (CC Only) =====================

// Get All Teachers
app.get("/api/teachers", authenticate, authorize(["CC"]), async (req, res) => {
  try {
    const teachers = await Teacher.find()
      .select("-password")
      .populate("assignedPeriods.classId", "name section");

    res.json(teachers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Teacher (CC Only)
app.post(
  "/api/teachers",
  authenticate,
  authorize(["CC"]),
  auditLog("CREATE_TEACHER"),
  [
    body("email").isEmail().normalizeEmail(),
    body("name").notEmpty(),
    body("password").isLength({ min: 6 }),
    body("role").optional().isIn(["CC", "STAFF"]),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const teacher = await Teacher.create(req.body);

      res.status(201).json({
        id: teacher._id,
        name: teacher.name,
        email: teacher.email,
        role: teacher.role,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// ===================== SCHEDULED TASKS =====================

// Auto-mark absent at 11:00 AM
cron.schedule("0 11 * * 1-6", async () => {
  try {
    const today = new Date().setHours(0, 0, 0, 0);

    // Check if holiday
    const holidayStatus = await AttendanceService.isHoliday(new Date());
    if (holidayStatus.isHoliday) return;

    // Get all active students
    const students = await Student.find({ isActive: true });

    for (const student of students) {
      // Check if campus attendance exists
      const campusAttendance = await Attendance.findOne({
        studentId: student._id,
        date: today,
        type: "CAMPUS",
      });

      if (!campusAttendance) {
        // Mark absent
        await Attendance.create({
          studentId: student._id,
          classId: student.classId,
          date: new Date(),
          type: "CAMPUS",
          status: "ABSENT",
        });

        // Send notification
        await NotificationService.notifyUser(
          student._id,
          "student",
          "Marked Absent",
          "You have been marked absent for today. Please submit reason."
        );
      }
    }

    console.log("Auto-absent marking completed");
  } catch (error) {
    console.error("Auto-absent error:", error);
  }
});

// Clean up expired sessions every hour
cron.schedule("0 * * * *", async () => {
  try {
    await Session.updateMany(
      {
        isActive: true,
        expiresAt: { $lt: new Date() },
      },
      { isActive: false }
    );
    console.log("Expired sessions cleaned up");
  } catch (error) {
    console.error("Session cleanup error:", error);
  }
});

// ===================== SAMPLE DATA SEEDER =====================

async function seedSampleData() {
  try {
    // Check if data already exists
    const existingTeacher = await Teacher.findOne({
      email: "sivaprakash7223@gmail.com",
    });
    if (existingTeacher) {
      console.log("Sample data already exists");
      return;
    }

    // Create CC teacher
    const ccTeacher = await Teacher.create({
      email: "sivaprakash7223@gmail.com",
      name: "Sivaprakash",
      password: "admin123",
      role: "CC",
    });

    // Create staff teachers
    const staffTeachers = await Teacher.create([
      {
        email: "john.doe@school.edu",
        name: "John Doe",
        password: "staff123",
        role: "STAFF",
      },
      {
        email: "jane.smith@school.edu",
        name: "Jane Smith",
        password: "staff123",
        role: "STAFF",
      },
    ]);

    // Create classes
    const classes = await Class.create([
      {
        name: "CSE2021",
        section: "A",
        year: 3,
        createdBy: ccTeacher._id,
        timetable: {
          monday: [
            {
              period: 1,
              staffId: staffTeachers[0]._id,
              subject: "Data Structures",
            },
            {
              period: 2,
              staffId: staffTeachers[1]._id,
              subject: "Database Systems",
            },
          ],
          tuesday: [
            {
              period: 1,
              staffId: staffTeachers[1]._id,
              subject: "Database Systems",
            },
            {
              period: 2,
              staffId: staffTeachers[0]._id,
              subject: "Data Structures",
            },
          ],
        },
      },
      {
        name: "CSE2021",
        section: "B",
        year: 3,
        createdBy: ccTeacher._id,
      },
    ]);

    // Create sample students
    const students = await Student.create([
      {
        name: "Alice Johnson",
        rollNumber: "CSE202100001",
        pin: "1234",
        classId: classes[0]._id,
      },
      {
        name: "Bob Wilson",
        rollNumber: "CSE202100002",
        pin: "5678",
        classId: classes[0]._id,
      },
      {
        name: "Charlie Brown",
        rollNumber: "CSE202100003",
        pin: "9012",
        classId: classes[1]._id,
      },
    ]);

    console.log("Sample data seeded successfully");
    console.log("CC Login: sivaprakash7223@gmail.com / admin123");
    console.log("Staff Login: john.doe@school.edu / staff123");
    console.log("Student Login: CSE202100001 / 1234");
  } catch (error) {
    console.error("Seeding error:", error);
  }
}

// Error handler middleware
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);

  // Seed sample data on first run
  seedSampleData();
});

module.exports = app;
