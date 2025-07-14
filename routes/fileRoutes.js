const express = require("express");
const router = express.Router();
const multer = require("multer");
const cloudinary = require("../utils/cloudinary");
const File = require("../models/File");
const User = require("../models/User"); // Add User model import
const crypto = require("crypto");
const streamifier = require("streamifier");
const dotenv = require("dotenv");
const axios = require("axios"); // Add axios for better HTTP requests
const jwt = require("jsonwebtoken");
dotenv.config();

// Authentication middleware
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "No authentication token provided"
      });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: "Token expired",
          error: err.message
        });
      }
      return res.status(403).json({
        success: false,
        message: "Invalid token",
        error: err.message
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Authentication failed",
      error: err.message
    });
  }
};

// Multer in-memory storage
const upload = multer({ storage: multer.memoryStorage() });

// AES-256-CBC encryption config
const algorithm = "aes-256-cbc";
const secretKey = Buffer.from(process.env.SECRET_KEY, "hex");
const iv = Buffer.from(process.env.IV, "hex");

// Encrypt buffer with AES
const encryptBuffer = (buffer) => {
  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
  return Buffer.concat([cipher.update(buffer), cipher.final()]);
};

// 🔐 Upload encrypted file
router.post("/upload", [authenticateToken, upload.single("file")], async (req, res) => {
  try {
    let { recipient, aesKeyHash, unlockTime } = req.body;
    const file = req.file;

    if (!file || !recipient || !aesKeyHash || !unlockTime) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Get sender from authenticated user
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Trim all inputs to avoid invisible characters
    recipient = recipient.trim();
    aesKeyHash = aesKeyHash.trim();

    // Store original file name and encrypted file name separately
    const originalFileName = file.originalname;
    const encryptedFileName = originalFileName + ".enc";

    // Encrypt file buffer
    const encryptedBuffer = encryptBuffer(file.buffer);

    // Upload to Cloudinary
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        resource_type: "raw",
        folder: "user_uploads",
        public_id: encryptedFileName,
      },
      async (error, result) => {
        if (error) {
          return res.status(500).json({ message: "Cloudinary upload failed", error: error.message });
        }

        // Save file metadata
        const newFile = new File({
          sender: user.walletAddress,
          recipient,
          fileUrl: result.secure_url,
          fileName: encryptedFileName,
          originalFileName, // Store original file name
          aesKeyHash,
          unlockTime,
        });

        await newFile.save();

        // Increment filesShared counter
        user.filesShared += 1;
        await user.save();

        // Find recipient user and increment their filesReceived counter
        const recipientUser = await User.findOne({ walletAddress: recipient });
        if (recipientUser) {
          recipientUser.filesReceived += 1;
          await recipientUser.save();
        }

        res.status(201).json({ 
          message: "Encrypted file uploaded", 
          file: {
            ...newFile.toObject(),
            senderUsername: user.username
          }
        });
      }
    );

    streamifier.createReadStream(encryptedBuffer).pipe(uploadStream);
  } catch (err) {
    res.status(500).json({ message: "Upload failed", error: err.message });
  }
});

// 📥 Get all files received by a user
router.get("/received/:recipient", async (req, res) => {
  try {
    const recipient = req.params.recipient.trim();

    // Find files with populated sender information
    const receivedFiles = await File.find({
      recipient: new RegExp(`^${recipient}$`, "i") // case-insensitive match
    }).sort({ createdAt: -1 }); // Sort by newest first

    if (!receivedFiles.length) {
      return res.status(200).json({ 
        success: true,
        message: "No files received yet", 
        files: [] 
      });
    }

    // Get unique sender addresses
    const senderAddresses = [...new Set(receivedFiles.map(file => file.sender))];
    
    // Find all senders' information
    const senders = await User.find({
      walletAddress: { $in: senderAddresses }
    });

    // Create a map of wallet address to user info
    const senderMap = new Map(
      senders.map(sender => [
        sender.walletAddress.toLowerCase(),
        {
          username: sender.username,
          walletAddress: sender.walletAddress
        }
      ])
    );

    const formatted = receivedFiles.map(file => {
      // Safely handle file names
      let displayName = 'Unnamed File';
      let encryptedName = file.fileName || 'unknown.enc';
      
      if (file.originalFileName) {
        displayName = file.originalFileName;
      } else if (file.fileName) {
        displayName = file.fileName.endsWith('.enc') 
          ? file.fileName.slice(0, -4)  // remove .enc
          : file.fileName;
      }

      // Get sender info from map
      const senderInfo = senderMap.get(file.sender.toLowerCase()) || {
        username: 'Unknown User',
        walletAddress: file.sender
      };

      return {
        fileName: displayName,
        encryptedFileName: encryptedName,
        sender: senderInfo.walletAddress,
        senderUsername: senderInfo.username,
        fileUrl: file.fileUrl,
        unlockTime: file.unlockTime,
        createdAt: file.createdAt,
        id: file._id
      };
    });

    res.status(200).json({ 
      success: true,
      message: "Files retrieved successfully",
      files: formatted 
    });
  } catch (err) {
    res.status(500).json({ 
      success: false,
      message: "Failed to retrieve received files", 
      error: err.message 
    });
  }
});

// ⬇️ Download + Decrypt File
router.post("/download/:fileId", authenticateToken, async (req, res) => {
  try {
    const { fileId } = req.params;
    const { aesKey } = req.body;

    // Validate input
    if (!fileId || !aesKey) {
      return res.status(400).json({ message: "Missing required parameters" });
    }

    // Find the file
    const fileDoc = await File.findById(fileId);
    if (!fileDoc) {
      return res.status(404).json({ message: "File not found" });
    }

    // Check if user is authorized to download (must be recipient)
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Case-insensitive comparison of wallet addresses
    if (fileDoc.recipient.toLowerCase() !== user.walletAddress.toLowerCase()) {
      return res.status(403).json({ 
        message: "You are not authorized to download this file. Only the recipient can download it.",
        details: {
          recipient: fileDoc.recipient,
          yourAddress: user.walletAddress
        }
      });
    }

    // Validate AES key
    const trimmedKey = aesKey.trim();
    const keyHash = crypto.createHash("sha256").update(trimmedKey).digest("hex");

    if (keyHash !== fileDoc.aesKeyHash.trim()) {
      return res.status(403).json({ 
        message: "Invalid decryption key. Please check the key provided by the sender." 
      });
    }

    // Check unlock time
    const now = new Date();
    const unlockTime = new Date(fileDoc.unlockTime);
    if (now < unlockTime) {
      const timeLeft = Math.ceil((unlockTime - now) / (1000 * 60)); // minutes
      return res.status(403).json({ 
        message: `File is still locked. Available in ${timeLeft} minutes (${unlockTime.toLocaleString()})` 
      });
    }

    try {
      // Fetch encrypted file from Cloudinary
      const response = await axios.get(fileDoc.fileUrl, {
        responseType: 'arraybuffer',
        timeout: 30000 // 30 second timeout
      });

      const encryptedBuffer = Buffer.from(response.data);

      // Decrypt
      const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
      const decryptedBuffer = Buffer.concat([
        decipher.update(encryptedBuffer),
        decipher.final()
      ]);

      // Use original file name if available, otherwise remove .enc extension
      const downloadFileName = fileDoc.originalFileName || fileDoc.fileName.replace(".enc", "");

      // Set headers for file download
      res.setHeader("Content-Disposition", `attachment; filename="${downloadFileName}"`);
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Length", decryptedBuffer.length);
      
      // Send the file
      res.send(decryptedBuffer);
    } catch (error) {
      
      if (error.response) {
        // Cloudinary error
        return res.status(500).json({ 
          message: "Failed to fetch file from storage",
          error: error.message 
        });
      } else if (error.code === 'ERR_BAD_REQUEST') {
        return res.status(400).json({ 
          message: "Invalid file URL" 
        });
      } else {
        return res.status(500).json({ 
          message: "Error processing file",
          error: error.message 
        });
      }
    }
  } catch (err) {
    res.status(500).json({ 
      message: "File download failed", 
      error: err.message 
    });
  }
});

// 🔑 Verify AES key before download
router.post("/verify-key/:fileId", authenticateToken, async (req, res) => {
  try {
    const { fileId } = req.params;
    const { aesKey } = req.body;

    // Validate input
    if (!fileId || !aesKey) {
      return res.status(400).json({
        success: false,
        message: "Missing required parameters",
        details: {
          fileId: !fileId ? "File ID is required" : null,
          aesKey: !aesKey ? "Decryption key is required" : null
        }
      });
    }

    // Find the file
    const fileDoc = await File.findById(fileId);

    if (!fileDoc) {
      return res.status(404).json({
        success: false,
        message: "File not found",
        details: { fileId }
      });
    }

    // Check if user is authorized (must be recipient)
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
        details: { userId: req.user.id }
      });
    }

    // Case-insensitive comparison of wallet addresses
    const recipientMatch = fileDoc.recipient.toLowerCase() === user.walletAddress.toLowerCase();

    if (!recipientMatch) {
      return res.status(403).json({
        success: false,
        message: "You are not authorized to access this file. Only the recipient can access it.",
        details: {
          recipient: fileDoc.recipient,
          yourAddress: user.walletAddress
        }
      });
    }

    // Validate AES key
    const trimmedKey = aesKey.trim();
    const keyHash = crypto.createHash("sha256").update(trimmedKey).digest("hex");

    if (keyHash !== fileDoc.aesKeyHash.trim()) {
      return res.status(403).json({
        success: false,
        message: "Invalid decryption key. Please check the key provided by the sender.",
        details: {
          isValid: false
        }
      });
    }

    // Check unlock time
    const now = new Date();
    const unlockTime = new Date(fileDoc.unlockTime);
    if (now < unlockTime) {
      const timeLeft = Math.ceil((unlockTime - now) / (1000 * 60)); // minutes
      return res.status(403).json({
        success: false,
        message: `File is still locked. Available in ${timeLeft} minutes (${unlockTime.toLocaleString()})`,
        details: {
          unlockTime,
          timeLeft,
          currentTime: now
        }
      });
    }

    // If we get here, the key is valid
    res.status(200).json({
      success: true,
      message: "Key verified successfully",
      data: {
        fileName: fileDoc.originalFileName || fileDoc.fileName.replace('.enc', ''),
        fileId: fileDoc._id,
        sender: fileDoc.sender,
        unlockTime: fileDoc.unlockTime
      }
    });

  } catch (err) {
    // Handle specific error types
    if (err.name === 'CastError') {
      return res.status(400).json({
        success: false,
        message: "Invalid file ID format",
        error: err.message
      });
    }
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: "Authentication token has expired",
        error: err.message
      });
    }

    res.status(500).json({
      success: false,
      message: "Key verification failed",
      error: err.message
    });
  }
});

module.exports = router;
