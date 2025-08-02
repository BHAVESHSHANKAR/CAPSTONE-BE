const express = require("express");
const router = express.Router();
const multer = require("multer");
const cloudinary = require("../utils/cloudinary");
const File = require("../models/File");
const User = require("../models/User");
const crypto = require("crypto");
const streamifier = require("streamifier");
const dotenv = require("dotenv");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const { transporter } = require("../utils/emailConfig");
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

// 📋 Get user's file history (both sent and received)
router.get("/history/:walletAddress", authenticateToken, async (req, res) => {
  try {
    const walletAddress = req.params.walletAddress.trim();

    // Find files where user is either sender or recipient
    const files = await File.find({
      $or: [
        { sender: new RegExp(`^${walletAddress}$`, "i") },
        { recipient: new RegExp(`^${walletAddress}$`, "i") }
      ]
    }).sort({ createdAt: -1 }); // Sort by newest first

    if (!files.length) {
      return res.status(200).json({
        success: true,
        message: "No file history found",
        files: []
      });
    }

    // Get unique wallet addresses for both senders and recipients
    const walletAddresses = [...new Set([
      ...files.map(file => file.sender),
      ...files.map(file => file.recipient)
    ])];

    // Find all users' information
    const users = await User.find({
      walletAddress: { $in: walletAddresses }
    });

    // Create a map of wallet address to user info
    const userMap = new Map(
      users.map(user => [
        user.walletAddress.toLowerCase(),
        {
          username: user.username,
          walletAddress: user.walletAddress
        }
      ])
    );

    const formatted = files.map(file => {
      // Get sender and recipient info
      const senderInfo = userMap.get(file.sender.toLowerCase()) || {
        username: 'Unknown User',
        walletAddress: file.sender
      };

      const recipientInfo = userMap.get(file.recipient.toLowerCase()) || {
        username: 'Unknown User',
        walletAddress: file.recipient
      };

      // Determine if the current user is the sender or recipient
      const isSender = file.sender.toLowerCase() === walletAddress.toLowerCase();

      // Format file name
      let displayName = file.originalFileName || file.fileName.replace('.enc', '');

      return {
        id: file._id,
        fileName: displayName,
        type: isSender ? 'sent' : 'received',
        sender: {
          address: senderInfo.walletAddress,
          username: senderInfo.username
        },
        recipient: {
          address: recipientInfo.walletAddress,
          username: recipientInfo.username
        },
        unlockTime: file.unlockTime,
        createdAt: file.createdAt
      };
    });

    res.status(200).json({
      success: true,
      message: "File history retrieved successfully",
      files: formatted
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Failed to retrieve file history",
      error: err.message
    });
  }
});

// 📧 Send email notification to recipient
router.post("/notify", authenticateToken, async (req, res) => {
  try {
    const { recipient, fileName, aesKey, txHash, unlockTime, sender } = req.body;

    // Find recipient user to get their email
    const recipientUser = await User.findOne({ walletAddress: recipient });
    if (!recipientUser || !recipientUser.email) {
      return res.status(404).json({
        success: false,
        message: "Recipient email not found"
      });
    }

    // Verify email configuration
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.error('Email configuration missing');
      return res.status(500).json({
        success: false,
        message: "Email service not configured properly"
      });
    }

    // Email template
    const emailContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #2563eb;">New Secure File Shared With You</h2>
        
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <p><strong>From:</strong> ${sender}</p>
          <p><strong>File Name:</strong> ${fileName}</p>
          <p><strong>Unlock Time:</strong> ${unlockTime}</p>
        </div>

        <div style="background-color: #fff7ed; padding: 20px; border-radius: 8px; border: 1px solid #fed7aa; margin: 20px 0;">
          <h3 style="color: #9a3412; margin-top: 0;">Decryption Key</h3>
          <p style="font-family: monospace; background-color: #fff; padding: 10px; border-radius: 4px; word-break: break-all;">
            ${aesKey}
          </p>
          <p style="color: #9a3412; font-size: 14px;">⚠️ Save this key! You'll need it to decrypt the file.</p>
        </div>

        <div style="background-color: #f0f9ff; padding: 20px; border-radius: 8px; border: 1px solid #bae6fd; margin: 20px 0;">
          <h3 style="color: #0369a1; margin-top: 0;">Blockchain Transaction</h3>
          <p style="font-family: monospace; background-color: #fff; padding: 10px; border-radius: 4px; word-break: break-all;">
            ${txHash}
          </p>
        </div>

        <p style="color: #4b5563; font-size: 14px;">
          You can access this file through your dashboard once the unlock time is reached.
          Keep the decryption key safe until you're ready to download the file.
        </p>
      </div>
    `;

    // Send email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: recipientUser.email,
      subject: `Secure File Shared: ${fileName}`,
      html: emailContent
    });

    res.status(200).json({
      success: true,
      message: "Email notification sent successfully"
    });

  } catch (err) {
    console.error('Email notification error:', err);
    res.status(500).json({
      success: false,
      message: "Failed to send email notification",
      error: err.message
    });
  }
});

// 🗑️ Delete file (recipient only)
router.delete("/delete/:fileId", authenticateToken, async (req, res) => {
  try {
    const { fileId } = req.params;

    // Validate input
    if (!fileId) {
      return res.status(400).json({
        success: false,
        message: "File ID is required"
      });
    }

    // Find the file
    const fileDoc = await File.findById(fileId);
    if (!fileDoc) {
      return res.status(404).json({
        success: false,
        message: "File not found"
      });
    }

    // Check if user is authorized to delete (must be recipient)
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    // Case-insensitive comparison of wallet addresses
    if (fileDoc.recipient.toLowerCase() !== user.walletAddress.toLowerCase()) {
      return res.status(403).json({
        success: false,
        message: "You are not authorized to delete this file. Only the recipient can delete it.",
        details: {
          recipient: fileDoc.recipient,
          yourAddress: user.walletAddress
        }
      });
    }

    try {
      // Delete from Cloudinary
      if (fileDoc.fileUrl) {
        // Extract public_id from Cloudinary URL
        const urlParts = fileDoc.fileUrl.split('/');
        const publicIdWithExtension = urlParts[urlParts.length - 1];
        const publicId = `user_uploads/${publicIdWithExtension}`;
        
        try {
          await cloudinary.uploader.destroy(publicId, { resource_type: 'raw' });
          console.log(`Successfully deleted file from Cloudinary: ${publicId}`);
        } catch (cloudinaryError) {
          console.error('Cloudinary deletion error:', cloudinaryError);
          // Continue with database deletion even if Cloudinary fails
        }
      }

      // Delete from MongoDB
      await File.findByIdAndDelete(fileId);

      // Update user counters
      const recipientUser = await User.findOne({ walletAddress: fileDoc.recipient });
      if (recipientUser && recipientUser.filesReceived > 0) {
        recipientUser.filesReceived -= 1;
        await recipientUser.save();
      }

      const senderUser = await User.findOne({ walletAddress: fileDoc.sender });
      if (senderUser && senderUser.filesShared > 0) {
        senderUser.filesShared -= 1;
        await senderUser.save();
      }

      res.status(200).json({
        success: true,
        message: "File deleted successfully from all storage locations",
        deletedFile: {
          id: fileDoc._id,
          fileName: fileDoc.originalFileName || fileDoc.fileName,
          sender: fileDoc.sender,
          recipient: fileDoc.recipient
        }
      });

    } catch (deletionError) {
      console.error('File deletion error:', deletionError);
      res.status(500).json({
        success: false,
        message: "Failed to delete file from storage",
        error: deletionError.message
      });
    }

  } catch (err) {
    console.error('Delete file error:', err);
    
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
      message: "File deletion failed",
      error: err.message
    });
  }
});


module.exports = router;
