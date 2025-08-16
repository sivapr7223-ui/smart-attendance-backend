const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const { Teacher, Student, Audit } = require("./models");

// JWT Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.type === "teacher") {
      const teacher = await Teacher.findById(decoded.id).select("-password");
      if (!teacher) {
        throw new Error();
      }
      req.user = teacher;
      req.userType = "teacher";
    } else if (decoded.type === "student") {
      const student = await Student.findById(decoded.id).select("-pin");
      if (!student) {
        throw new Error();
      }

      // Verify device binding
      if (student.deviceId && student.deviceId !== req.header("X-Device-Id")) {
        return res
          .status(403)
          .json({ error: "Device mismatch. Please use registered device." });
      }

      req.user = student;
      req.userType = "student";
    }

    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid authentication token" });
  }
};

// Role-based Access Control
const authorize = (roles) => {
  return (req, res, next) => {
    if (req.userType !== "teacher") {
      return res.status(403).json({ error: "Access denied. Teachers only." });
    }

    if (roles && !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }

    next();
  };
};

// Validation Error Handler
const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Audit Logger
const auditLog = (action) => {
  return async (req, res, next) => {
    const originalSend = res.send;

    res.send = async function (data) {
      res.send = originalSend;

      if (res.statusCode < 400) {
        try {
          await Audit.create({
            userId: req.user._id,
            userType: req.userType.toUpperCase(),
            action,
            details: {
              method: req.method,
              path: req.path,
              body: req.body,
              params: req.params,
              query: req.query,
            },
            ip: req.ip,
            userAgent: req.get("user-agent"),
          });
        } catch (error) {
          console.error("Audit log error:", error);
        }
      }

      return res.send(data);
    };

    next();
  };
};

// Error Handler
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);

  if (err.name === "ValidationError") {
    return res.status(400).json({
      error: "Validation Error",
      details: Object.values(err.errors).map((e) => e.message),
    });
  }

  if (err.code === 11000) {
    return res.status(400).json({
      error: "Duplicate Entry",
      field: Object.keys(err.keyPattern)[0],
    });
  }

  res.status(500).json({ error: "Internal Server Error" });
};

module.exports = {
  authenticate,
  authorize,
  handleValidation,
  auditLog,
  errorHandler,
};
