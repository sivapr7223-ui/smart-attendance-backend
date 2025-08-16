const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// Teacher Schema
const teacherSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["CC", "STAFF"], default: "STAFF" },
  assignedPeriods: [
    {
      classId: { type: mongoose.Schema.Types.ObjectId, ref: "Class" },
      period: { type: Number, min: 1, max: 8 },
    },
  ],
  fcmToken: String,
  createdAt: { type: Date, default: Date.now },
});

teacherSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

teacherSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Student Schema
const studentSchema = new mongoose.Schema({
  rollNumber: { type: String, required: true, unique: true, length: 12 },
  name: { type: String, required: true },
  pin: { type: String, required: true, length: 4 },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: true,
  },
  deviceId: String,
  deviceInfo: {
    model: String,
    platform: String,
    uuid: String,
  },
  fcmToken: String,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

studentSchema.pre("save", async function (next) {
  if (!this.isModified("pin")) return next();
  this.pin = await bcrypt.hash(this.pin, 10);
  next();
});

studentSchema.methods.comparePin = async function (pin) {
  return await bcrypt.compare(pin, this.pin);
};

// Class Schema
const classSchema = new mongoose.Schema({
  name: { type: String, required: true },
  section: { type: String, required: true },
  year: { type: Number, required: true },
  timetable: {
    monday: [
      {
        period: Number,
        staffId: mongoose.Schema.Types.ObjectId,
        subject: String,
      },
    ],
    tuesday: [
      {
        period: Number,
        staffId: mongoose.Schema.Types.ObjectId,
        subject: String,
      },
    ],
    wednesday: [
      {
        period: Number,
        staffId: mongoose.Schema.Types.ObjectId,
        subject: String,
      },
    ],
    thursday: [
      {
        period: Number,
        staffId: mongoose.Schema.Types.ObjectId,
        subject: String,
      },
    ],
    friday: [
      {
        period: Number,
        staffId: mongoose.Schema.Types.ObjectId,
        subject: String,
      },
    ],
    saturday: [
      {
        period: Number,
        staffId: mongoose.Schema.Types.ObjectId,
        subject: String,
      },
    ],
  },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "Teacher" },
  createdAt: { type: Date, default: Date.now },
});

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Student",
    required: true,
  },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: true,
  },
  date: { type: Date, required: true },
  type: { type: String, enum: ["CAMPUS", "CLASS"], required: true },
  period: { type: Number, min: 1, max: 8 },
  status: {
    type: String,
    enum: ["PRESENT", "ABSENT", "LATE"],
    default: "ABSENT",
  },
  mode: { type: String, enum: ["GPS", "BLE", "WIFI", "INTERNET", "MANUAL"] },
  location: {
    latitude: Number,
    longitude: Number,
  },
  deviceId: String,
  markedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Teacher" },
  reason: String,
  createdAt: { type: Date, default: Date.now },
});

// Attendance Session Schema
const sessionSchema = new mongoose.Schema({
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: true,
  },
  teacherId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Teacher",
    required: true,
  },
  date: { type: Date, required: true },
  period: { type: Number, min: 1, max: 8, required: true },
  mode: { type: String, enum: ["BLE", "WIFI", "INTERNET"], required: true },
  token: { type: String, required: true, unique: true },
  code: String,
  ssid: String,
  isActive: { type: Boolean, default: true },
  expiresAt: { type: Date, required: true },
  presentStudents: [{ type: mongoose.Schema.Types.ObjectId, ref: "Student" }],
  createdAt: { type: Date, default: Date.now },
});

// Request Schema
const requestSchema = new mongoose.Schema({
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Student",
    required: true,
  },
  type: {
    type: String,
    enum: ["MANUAL_ATTENDANCE", "FRIEND_ATTENDANCE"],
    required: true,
  },
  date: { type: Date, required: true },
  period: Number,
  reason: { type: String, required: true },
  friendRollNumber: String,
  status: {
    type: String,
    enum: ["PENDING", "APPROVED", "REJECTED"],
    default: "PENDING",
  },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Teacher" },
  reviewNote: String,
  createdAt: { type: Date, default: Date.now },
});

// Holiday Schema
const holidaySchema = new mongoose.Schema({
  name: { type: String, required: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  type: { type: String, enum: ["SPECIAL", "SATURDAY_WORKING"], required: true },
  mappedDay: {
    type: String,
    enum: ["monday", "tuesday", "wednesday", "thursday", "friday"],
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Teacher",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});

// Audit Log Schema
const auditSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  userType: { type: String, enum: ["TEACHER", "STUDENT"], required: true },
  action: { type: String, required: true },
  details: mongoose.Schema.Types.Mixed,
  ip: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now },
});

// Export Models
module.exports = {
  Teacher: mongoose.model("Teacher", teacherSchema),
  Student: mongoose.model("Student", studentSchema),
  Class: mongoose.model("Class", classSchema),
  Attendance: mongoose.model("Attendance", attendanceSchema),
  Session: mongoose.model("Session", sessionSchema),
  Request: mongoose.model("Request", requestSchema),
  Holiday: mongoose.model("Holiday", holidaySchema),
  Audit: mongoose.model("Audit", auditSchema),
};
