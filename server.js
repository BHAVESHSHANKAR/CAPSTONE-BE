const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const authRoutes = require("./routes/authRoutes");
const fileRoutes = require("./routes/fileRoutes");
const { verifyEmailConfig } = require("./utils/emailConfig");
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5050;

// Configure CORS with specific options
app.use(cors({
  origin: process.env.FRONTEND_URL, // Allow both localhost and IP
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Disposition', 'Content-Length'],
  credentials: true
}));

// Increase payload limit for file uploads
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  console.log('Headers:', req.headers);
  next();
});

// Test route
app.get("/", (req, res) => res.send("Server is running"));

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);

// Global error handler with improved error responses
app.use((err, req, res, next) => {
  console.error("Server error:", err.stack);
  
  // Handle specific types of errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      success: false,
      message: "Validation error", 
      errors: Object.values(err.errors).map(e => e.message)
    });
  }
  
  if (err.name === 'UnauthorizedError' || err.name === 'TokenExpiredError') {
    return res.status(401).json({ 
      success: false,
      message: err.name === 'TokenExpiredError' ? "Token expired" : "Authentication error",
      error: err.message 
    });
  }
  
  if (err.name === 'ForbiddenError') {
    return res.status(403).json({
      success: false,
      message: "Access denied",
      error: err.message
    });
  }
  
  // Default error response
  res.status(err.status || 500).json({ 
    success: false,
    message: err.message || "Internal server error",
    error: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(async () => {
    console.log("✅ MongoDB connected");
    
    // Verify email configuration
    const emailConfigured = await verifyEmailConfig();
    if (!emailConfigured) {
      console.warn("⚠️ Email service not configured properly. Email notifications will not work.");
    }

    app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });