const crypto = require("crypto");
const PDFDocument = require("pdfkit");
const { Parser } = require("json2csv");
const admin = require("firebase-admin");
const {
  Session,
  Attendance,
  Student,
  Teacher,
  Class,
  Holiday,
} = require("./models");

// Initialize Firebase Admin
const initializeFirebase = () => {
  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      }),
    });
    console.log("Firebase initialized successfully");
  } catch (error) {
    console.error("Firebase initialization error:", error);
  }
};

// Attendance Service
class AttendanceService {
  // Generate secure token for attendance session
  static generateToken() {
    return crypto.randomBytes(32).toString("hex");
  }

  // Generate short code for internet mode
  static generateCode() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
  }

  // Check if point is within campus bounds
  static isWithinCampus(latitude, longitude) {
    // Example campus coordinates - replace with actual
    const CAMPUS_CENTER = { lat: 13.0827, lng: 80.2707 };
    const CAMPUS_RADIUS = 500; // meters

    const distance = this.calculateDistance(
      CAMPUS_CENTER.lat,
      CAMPUS_CENTER.lng,
      latitude,
      longitude
    );

    return distance <= CAMPUS_RADIUS;
  }

  // Calculate distance between two points
  static calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371e3; // Earth's radius in meters
    const φ1 = (lat1 * Math.PI) / 180;
    const φ2 = (lat2 * Math.PI) / 180;
    const Δφ = ((lat2 - lat1) * Math.PI) / 180;
    const Δλ = ((lon2 - lon1) * Math.PI) / 180;

    const a =
      Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
      Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
  }

  // Create attendance session
  static async createSession(classId, teacherId, period, mode) {
    const token = this.generateToken();
    const code = mode === "INTERNET" ? this.generateCode() : null;
    const ssid =
      mode === "WIFI" ? `SmartAttend_${token.substring(0, 8)}` : null;

    const session = await Session.create({
      classId,
      teacherId,
      date: new Date(),
      period,
      mode,
      token,
      code,
      ssid,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    });

    // Send notifications to students
    await NotificationService.notifyClassStudents(
      classId,
      "Attendance Session Started",
      `Period ${period} attendance is now open. Mode: ${mode}`
    );

    return session;
  }

  // Mark attendance
  static async markAttendance(sessionId, studentId, deviceId, location) {
    const session = await Session.findById(sessionId);
    if (!session || !session.isActive || session.expiresAt < new Date()) {
      throw new Error("Invalid or expired session");
    }

    // Check if already marked
    const existing = await Attendance.findOne({
      studentId,
      classId: session.classId,
      date: new Date().setHours(0, 0, 0, 0),
      period: session.period,
    });

    if (existing) {
      throw new Error("Attendance already marked");
    }

    // Create attendance record
    const attendance = await Attendance.create({
      studentId,
      classId: session.classId,
      date: new Date(),
      type: "CLASS",
      period: session.period,
      status: "PRESENT",
      mode: session.mode,
      location,
      deviceId,
      markedBy: session.teacherId,
    });

    // Update session
    session.presentStudents.push(studentId);
    await session.save();

    return attendance;
  }

  // Auto-mark campus attendance
  static async markCampusAttendance(studentId, location, deviceId) {
    const today = new Date().setHours(0, 0, 0, 0);

    // Check if already marked
    const existing = await Attendance.findOne({
      studentId,
      date: today,
      type: "CAMPUS",
    });

    if (existing) {
      return existing;
    }

    // Check time (before 11 AM)
    const now = new Date();
    if (now.getHours() >= 11) {
      throw new Error("Campus attendance closed after 11:00 AM");
    }

    // Verify location
    if (!this.isWithinCampus(location.latitude, location.longitude)) {
      throw new Error("Not within campus bounds");
    }

    const student = await Student.findById(studentId);
    const attendance = await Attendance.create({
      studentId,
      classId: student.classId,
      date: new Date(),
      type: "CAMPUS",
      status: "PRESENT",
      mode: "GPS",
      location,
      deviceId,
    });

    return attendance;
  }

  // Check holiday status
  static async isHoliday(date) {
    const dayOfWeek = date.getDay();

    // Sunday is always holiday
    if (dayOfWeek === 0) return { isHoliday: true, reason: "Sunday" };

    // Set date to start of day for comparison
    const checkDate = new Date(date);
    checkDate.setHours(0, 0, 0, 0);

    // Check for any holiday declarations for this date
    const holiday = await Holiday.findOne({
      startDate: { $lte: checkDate },
      endDate: { $gte: checkDate },
    });

    // Debug log
    console.log("Checking date:", checkDate);
    console.log("Found holiday record:", holiday);

    if (holiday) {
      if (holiday.type === "SPECIAL") {
        return { isHoliday: true, reason: holiday.name };
      }

      // If it's a Saturday working day declaration
      if (holiday.type === "SATURDAY_WORKING" && dayOfWeek === 6) {
        return {
          isHoliday: false, // Not a holiday
          isWorkingDay: true,
          mappedDay: holiday.mappedDay,
          reason: "Working Saturday",
        };
      }
    }

    // Default Saturday behavior (holiday if no working day declared)
    if (dayOfWeek === 6) {
      return { isHoliday: true, reason: "Saturday" };
    }

    // Regular weekday
    return { isHoliday: false };
  }
}

// Notification Service
class NotificationService {
  static async sendNotification(fcmToken, title, body, data = {}) {
    if (!fcmToken || !admin.apps.length) return;

    try {
      const message = {
        notification: { title, body },
        data: { ...data, timestamp: new Date().toISOString() },
        token: fcmToken,
      };

      await admin.messaging().send(message);
    } catch (error) {
      console.error("FCM send error:", error);
    }
  }

  static async notifyClassStudents(classId, title, body) {
    const students = await Student.find({
      classId,
      fcmToken: { $exists: true },
    });

    const notifications = students.map((student) =>
      this.sendNotification(student.fcmToken, title, body, {
        classId: classId.toString(),
      })
    );

    await Promise.all(notifications);
  }

  static async notifyUser(userId, userType, title, body, data = {}) {
    let user;
    if (userType === "student") {
      user = await Student.findById(userId);
    } else {
      user = await Teacher.findById(userId);
    }

    if (user?.fcmToken) {
      await this.sendNotification(user.fcmToken, title, body, data);
    }
  }
}

// Report Service
class ReportService {
  static async generateAttendanceReport(
    classId,
    startDate,
    endDate,
    format = "json"
  ) {
    const attendances = await Attendance.find({
      classId,
      date: { $gte: startDate, $lte: endDate },
    })
      .populate("studentId", "name rollNumber")
      .sort({ date: -1, period: 1 });

    const students = await Student.find({ classId }).sort("rollNumber");

    // Calculate statistics
    const stats = {};
    students.forEach((student) => {
      stats[student._id] = {
        name: student.name,
        rollNumber: student.rollNumber,
        totalClasses: 0,
        present: 0,
        absent: 0,
        percentage: 0,
      };
    });

    attendances.forEach((record) => {
      const studentId = record.studentId._id.toString();
      if (stats[studentId]) {
        stats[studentId].totalClasses++;
        if (record.status === "PRESENT") {
          stats[studentId].present++;
        } else {
          stats[studentId].absent++;
        }
      }
    });

    // Calculate percentages
    Object.values(stats).forEach((stat) => {
      if (stat.totalClasses > 0) {
        stat.percentage = Math.round((stat.present / stat.totalClasses) * 100);
      }
    });

    if (format === "csv") {
      return this.generateCSV(Object.values(stats));
    } else if (format === "pdf") {
      return this.generatePDF(
        classId,
        Object.values(stats),
        startDate,
        endDate
      );
    }

    return Object.values(stats);
  }

  static generateCSV(data) {
    const fields = [
      "rollNumber",
      "name",
      "totalClasses",
      "present",
      "absent",
      "percentage",
    ];
    const parser = new Parser({ fields });
    return parser.parse(data);
  }

  static async generatePDF(classId, data, startDate, endDate) {
    const classInfo = await Class.findById(classId);
    const doc = new PDFDocument();
    const chunks = [];

    doc.on("data", (chunk) => chunks.push(chunk));

    // Header
    doc.fontSize(20).text("Attendance Report", { align: "center" });
    doc.fontSize(14).text(`Class: ${classInfo.name} - ${classInfo.section}`, {
      align: "center",
    });
    doc
      .fontSize(12)
      .text(
        `Period: ${startDate.toDateString()} to ${endDate.toDateString()}`,
        { align: "center" }
      );
    doc.moveDown();

    // Table headers
    doc.fontSize(10);
    doc.text("Roll No", 50, doc.y, { width: 80 });
    doc.text("Name", 130, doc.y, { width: 150 });
    doc.text("Classes", 280, doc.y, { width: 60 });
    doc.text("Present", 340, doc.y, { width: 60 });
    doc.text("Absent", 400, doc.y, { width: 60 });
    doc.text("Percentage", 460, doc.y, { width: 80 });
    doc.moveDown();

    // Data rows
    data.forEach((student) => {
      if (doc.y > 700) {
        doc.addPage();
      }

      doc.text(student.rollNumber, 50, doc.y, { width: 80 });
      doc.text(student.name, 130, doc.y, { width: 150 });
      doc.text(student.totalClasses.toString(), 280, doc.y, { width: 60 });
      doc.text(student.present.toString(), 340, doc.y, { width: 60 });
      doc.text(student.absent.toString(), 400, doc.y, { width: 60 });
      doc.text(`${student.percentage}%`, 460, doc.y, { width: 80 });
      doc.moveDown(0.5);
    });

    doc.end();

    return new Promise((resolve) => {
      doc.on("end", () => {
        resolve(Buffer.concat(chunks));
      });
    });
  }
}

// Initialize services
initializeFirebase();

module.exports = {
  AttendanceService,
  NotificationService,
  ReportService,
};
