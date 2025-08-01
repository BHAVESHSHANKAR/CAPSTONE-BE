const express = require("express");
const router = express.Router();
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const dotenv=require("dotenv");
dotenv.config();

// Device type middleware
const checkDeviceType = (req, res, next) => {
  const userAgent = req.headers['user-agent'].toLowerCase();
  const isMobile = /mobile|iphone|ipad|android|blackberry|windows\s+phone/i.test(userAgent);
  const isTablet = /(tablet|ipad|playbook|silk)|(android(?!.*mobile))/i.test(userAgent);
  
  if (isMobile || isTablet) {
    return res.status(403).json({
      message: "Access denied. For security purposes, the dashboard is only accessible from desktop or laptop computers.",
      type: "DEVICE_RESTRICTION",
      isRestrictedDevice: true
    });
  }
  next();
};
// Email transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Generate random 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP via email
const sendOTP = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your SecureChain Wallet Address OTP',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2563eb;">SecureChain Wallet Verification</h2>
        <p>Your OTP for wallet address verification is:</p>
        <h1 style="color: #1e40af; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
        <p>This OTP will expire in 5 minutes.</p>
        <p style="color: #64748b; font-size: 12px;">If you didn't request this OTP, please ignore this email.</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
};

router.post("/register", async (req, res) => {
  const { username, email, password, walletAddress } = req.body;

  try {
    // Validate input format
    if (!username || !email || !password || !walletAddress) {
      return res.status(400).json({
        message: "All fields are required",
        type: "VALIDATION_ERROR",
        details: {
          username: !username ? "Username is required" : null,
          email: !email ? "Email is required" : null,
          password: !password ? "Password is required" : null,
          walletAddress: !walletAddress ? "Wallet address is required" : null
        }
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        message: "Please enter a valid email address",
        type: "VALIDATION_ERROR",
        field: "email"
      });
    }

    // Validate username length
    if (username.length < 3) {
      return res.status(400).json({
        message: "Username must be at least 3 characters long",
        type: "VALIDATION_ERROR",
        field: "username"
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters long",
        type: "VALIDATION_ERROR",
        field: "password"
      });
    }

    // Validate wallet address format
    const walletRegex = /^0x[a-fA-F0-9]{40}$/;
    if (!walletRegex.test(walletAddress)) {
      return res.status(400).json({
        message: "Please enter a valid Ethereum wallet address (0x...)",
        type: "VALIDATION_ERROR",
        field: "walletAddress"
      });
    }

    // Check for existing email
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({
        message: "This email address is already registered. Please use a different email or try logging in.",
        type: "DUPLICATE_ERROR",
        field: "email"
      });
    }

    // Check for existing wallet address (case-insensitive)
    const existingWallet = await User.findOne({ 
      walletAddress: { $regex: new RegExp(`^${walletAddress}$`, 'i') }
    });
    if (existingWallet) {
      return res.status(400).json({
        message: "This wallet address is already registered. Please use a different wallet address.",
        type: "DUPLICATE_ERROR",
        field: "walletAddress"
      });
    }

    // Create new user
    const newUser = await User.create({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password,
      walletAddress: walletAddress.toLowerCase().trim()
    });

    // Generate JWT
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({
      message: "Account created successfully!",
      type: "SUCCESS",
      user: {
        _id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        walletAddress: newUser.walletAddress,
        walletAddressVisible: newUser.walletAddressVisible,
        filesShared: newUser.filesShared,
        filesReceived: newUser.filesReceived,
        createdAt: newUser.createdAt,
      },
      token,
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      message: "An error occurred during registration. Please try again.",
      type: "SERVER_ERROR",
      error: err.message
    });
  }
});
router.post("/login", checkDeviceType, async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validate input format
    if (!email && !password) {
      return res.status(400).json({ 
        message: "Email and password are required",
        type: "VALIDATION_ERROR"
      });
    }

    if (!email) {
      return res.status(400).json({ 
        message: "Email is required",
        type: "VALIDATION_ERROR"
      });
    }

    if (!password) {
      return res.status(400).json({ 
        message: "Password is required",
        type: "VALIDATION_ERROR"
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        message: "Please enter a valid email address",
        type: "VALIDATION_ERROR"
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        message: "No account found with this email address",
        type: "AUTH_ERROR"
      });
    }

    // Check password
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ 
        message: "Incorrect password",
        type: "AUTH_ERROR"
      });
    }

    // Generate JWT
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.status(200).json({
      message: "Successfully logged in",
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        walletAddress: user.walletAddress,
        walletAddressVisible: user.walletAddressVisible,
        filesShared: user.filesShared,
        filesReceived: user.filesReceived,
        createdAt: user.createdAt,
      },
      token,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      message: "An error occurred during login. Please try again.",
      type: "SERVER_ERROR",
      error: err.message 
    });
  }
});
router.get("/wallet/:walletAddress", async (req, res) => {
  try {
    const walletAddress = req.params.walletAddress.toLowerCase();
    const user = await User.findOne({ walletAddress });

    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch user", details: err.message });
  }
});
router.get("/me", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (err) {
    res.status(401).json({ message: "Invalid token", error: err.message });
  }
});

// Generate OTP endpoint
router.post("/generate-otp", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token provided" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate new OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes expiry

    // Save OTP to user document
    user.otp = {
      code: otp,
      expiresAt
    };
    await user.save();

    // Send OTP via email
    await sendOTP(user.email, otp);

    res.json({ message: "OTP sent successfully", expiresAt });
  } catch (err) {
    res.status(500).json({ message: "Failed to generate OTP", error: err.message });
  }
});

// Verify OTP endpoint
router.post("/verify-otp", async (req, res) => {
  try {
    const { otp } = req.body;
    const token = req.headers.authorization?.split(" ")[1];
    
    if (!token) return res.status(401).json({ message: "No token provided" });
    if (!otp) return res.status(400).json({ message: "OTP is required" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) return res.status(404).json({ message: "User not found" });
    if (!user.otp?.code) return res.status(400).json({ message: "No OTP was generated" });
    
    // Check if OTP is expired
    if (new Date() > new Date(user.otp.expiresAt)) {
      user.otp = undefined;
      await user.save();
      return res.status(400).json({ message: "OTP has expired" });
    }

    // Verify OTP
    if (user.otp.code !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // Clear OTP and set wallet address as visible
    user.otp = undefined;
    user.walletAddressVisible = true;
    await user.save();

    res.json({ message: "OTP verified successfully", walletAddressVisible: true });
  } catch (err) {
    res.status(500).json({ message: "Failed to verify OTP", error: err.message });
  }
});

// Hide wallet address endpoint
router.post("/hide-wallet", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token provided" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) return res.status(404).json({ message: "User not found" });

    user.walletAddressVisible = false;
    await user.save();

    res.json({ message: "Wallet address hidden successfully", walletAddressVisible: false });
  } catch (err) {
    res.status(500).json({ message: "Failed to hide wallet address", error: err.message });
  }
});

// Search users endpoint
router.get("/search", async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) {
      return res.status(400).json({
        success: false,
        message: "Search query is required"
      });
    }

    // Search by username or wallet address (case-insensitive)
    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: 'i' } },
        { walletAddress: { $regex: query, $options: 'i' } }
      ]
    })
    .select('username walletAddress walletAddressVisible')
    .limit(5);

    // Format response to handle wallet address visibility
    const formattedUsers = users.map(user => ({
      username: user.username,
      walletAddress: user.walletAddressVisible ? user.walletAddress : 
        `${user.walletAddress.slice(0, 6)}...${user.walletAddress.slice(-4)}`,
      walletAddressVisible: user.walletAddressVisible
    }));

    res.json({
      success: true,
      users: formattedUsers
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Failed to search users",
      error: err.message
    });
  }
});

module.exports = router;