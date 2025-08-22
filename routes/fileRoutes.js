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

// Encryption configurations
const AES_ALGORITHM = "aes-256-cbc";
const DES_ALGORITHM = "des-ede3-cbc";
const secretKey = Buffer.from(process.env.SECRET_KEY, "hex");
const iv = Buffer.from(process.env.IV, "hex");

// Encryption functions for different algorithms
const encryptionMethods = {
  AES: (buffer, key) => {
    const cipher = crypto.createCipheriv(AES_ALGORITHM, key || secretKey, iv);
    return Buffer.concat([cipher.update(buffer), cipher.final()]);
  },

  DES: (buffer, key) => {
    // DES uses 24-byte key for 3DES
    const desKey = key ? Buffer.from(key.slice(0, 48), 'hex') : secretKey.subarray(0, 24);
    const desIv = iv.subarray(0, 8); // DES uses 8-byte IV
    const cipher = crypto.createCipheriv(DES_ALGORITHM, desKey, desIv);
    return Buffer.concat([cipher.update(buffer), cipher.final()]);
  },

};

// Decryption functions for different algorithms
const decryptionMethods = {
  AES: (buffer, key) => {
    const decipher = crypto.createDecipheriv(AES_ALGORITHM, key || secretKey, iv);
    return Buffer.concat([decipher.update(buffer), decipher.final()]);
  },

  DES: (buffer, key) => {
    const desKey = key ? Buffer.from(key.slice(0, 48), 'hex') : secretKey.subarray(0, 24);
    const desIv = iv.subarray(0, 8);
    const decipher = crypto.createDecipheriv(DES_ALGORITHM, desKey, desIv);
    return Buffer.concat([decipher.update(buffer), decipher.final()]);
  },

};

// 🔐 Upload encrypted file
router.post("/upload", [authenticateToken, upload.single("file")], async (req, res) => {
  try {
    let { recipient, keyHash, unlockTime, encryptionAlgorithm = 'AES' } = req.body;
    const file = req.file;

    if (!file || !recipient || !keyHash || !unlockTime) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Validate encryption algorithm
    if (!['AES', 'DES'].includes(encryptionAlgorithm)) {
      return res.status(400).json({ message: "Invalid encryption algorithm" });
    }

    // Get sender from authenticated user
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Trim all inputs to avoid invisible characters
    recipient = recipient.trim();
    keyHash = keyHash.trim();

    // Store original file name and encrypted file name separately
    const originalFileName = file.originalname;
    const encryptedFileName = `${originalFileName}.${encryptionAlgorithm.toLowerCase()}.enc`;

    // Encrypt file buffer based on selected algorithm
    let encryptedBuffer;
    try {
      switch (encryptionAlgorithm) {
        case 'AES':
          encryptedBuffer = encryptionMethods.AES(file.buffer);
          break;
        case 'DES':
          encryptedBuffer = encryptionMethods.DES(file.buffer);
          break;
        default:
          throw new Error('Unsupported encryption algorithm');
      }
    } catch (encryptionError) {
      return res.status(500).json({
        message: `${encryptionAlgorithm} encryption failed`,
        error: encryptionError.message
      });
    }

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
          originalFileName,
          encryptionAlgorithm,
          keyHash,

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
          message: `File encrypted with ${encryptionAlgorithm} and uploaded successfully`,
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
        encryptionAlgorithm: file.encryptionAlgorithm || 'AES',
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

    // Validate key based on encryption algorithm
    const trimmedKey = aesKey.trim();
    const keyHash = crypto.createHash("sha256").update(trimmedKey).digest("hex");

    if (keyHash !== fileDoc.keyHash.trim()) {
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

      // Decrypt based on algorithm
      let decryptedBuffer;
      const algorithm = fileDoc.encryptionAlgorithm || 'AES';

      try {
        switch (algorithm) {
          case 'AES':
            decryptedBuffer = decryptionMethods.AES(encryptedBuffer);
            break;
          case 'DES':
            decryptedBuffer = decryptionMethods.DES(encryptedBuffer);
            break;
          default:
            throw new Error('Unsupported encryption algorithm');
        }
      } catch (decryptionError) {
        return res.status(500).json({
          message: `${algorithm} decryption failed`,
          error: decryptionError.message
        });
      }

      // Use original file name if available, otherwise remove .enc extension
      const downloadFileName = fileDoc.originalFileName || fileDoc.fileName.replace(/\.(aes|des)\.enc$/, "");

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

    // Validate key
    const trimmedKey = aesKey.trim();
    const keyHash = crypto.createHash("sha256").update(trimmedKey).digest("hex");

    if (keyHash !== fileDoc.keyHash.trim()) {
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
    const { recipient, fileName, aesKey, encryptionAlgorithm = 'AES', txHash, unlockTime, sender } = req.body;

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

    // Algorithm-specific email template
    const getAlgorithmInfo = (algorithm) => {
      switch (algorithm) {
        case 'AES':
          return {
            name: 'AES-256',
            description: 'Advanced Encryption Standard - Fast and secure',
            color: '#059669',
            bgColor: '#ecfdf5',
            borderColor: '#a7f3d0'
          };
        case 'DES':
          return {
            name: '3DES',
            description: 'Triple Data Encryption Standard - Legacy compatibility',
            color: '#d97706',
            bgColor: '#fffbeb',
            borderColor: '#fde68a'
          };

        default:
          return {
            name: 'AES-256',
            description: 'Advanced Encryption Standard',
            color: '#059669',
            bgColor: '#ecfdf5',
            borderColor: '#a7f3d0'
          };
      }
    };

    const algorithmInfo = getAlgorithmInfo(encryptionAlgorithm);

    const emailContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9fafb;">
        <div style="background-color: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          <h2 style="color: #1f2937; margin-top: 0; text-align: center;">🔐 Secure File Shared With You</h2>
          
          <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0; color: #374151;">📄 File Details</h3>
            <p style="margin: 8px 0;"><strong>From:</strong> ${sender}</p>
            <p style="margin: 8px 0;"><strong>File Name:</strong> ${fileName}</p>
            <p style="margin: 8px 0;"><strong>Encryption:</strong> 
              <span style="background-color: ${algorithmInfo.bgColor}; color: ${algorithmInfo.color}; padding: 4px 8px; border-radius: 4px; font-weight: bold;">
                ${algorithmInfo.name}
              </span>
            </p>
            <p style="margin: 8px 0;"><strong>Unlock Time:</strong> ${unlockTime}</p>
            <p style="margin: 8px 0; font-size: 12px; color: #6b7280;">${algorithmInfo.description}</p>
          </div>

          <div style="background-color: ${algorithmInfo.bgColor}; padding: 20px; border-radius: 8px; border: 2px solid ${algorithmInfo.borderColor}; margin: 20px 0;">
            <h3 style="color: ${algorithmInfo.color}; margin-top: 0;">🔑 ${algorithmInfo.name} Decryption Key</h3>
            <div style="background-color: #fff; padding: 15px; border-radius: 6px; border: 1px solid ${algorithmInfo.borderColor}; margin: 10px 0;">
              <p style="font-family: 'Courier New', monospace; font-size: 14px; word-break: break-all; margin: 0; color: #1f2937;">
                ${aesKey}
              </p>
            </div>
            <p style="color: ${algorithmInfo.color}; font-size: 14px; margin: 10px 0;">
              ⚠️ <strong>Important:</strong> Save this key securely! You'll need it to decrypt the file.
            </p>
            ${encryptionAlgorithm === 'AES' ? `
              <p style="color: ${algorithmInfo.color}; font-size: 12px; margin: 5px 0;">
                💡 This AES-256 key provides military-grade encryption for your file.
              </p>
            ` : ''}
            ${encryptionAlgorithm === 'DES' ? `
              <p style="color: ${algorithmInfo.color}; font-size: 12px; margin: 5px 0;">
                💡 This 3DES key ensures compatibility with legacy systems.
              </p>
            ` : ''}
          </div>



          <div style="background-color: #f0f9ff; padding: 20px; border-radius: 8px; border: 1px solid #bae6fd; margin: 20px 0;">
            <h3 style="color: #0369a1; margin-top: 0;">⛓️ Blockchain Transaction</h3>
            <div style="background-color: #fff; padding: 15px; border-radius: 6px; border: 1px solid #bae6fd;">
              <p style="font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all; margin: 0; color: #1f2937;">
                ${txHash}
              </p>
            </div>
            <p style="color: #0369a1; font-size: 12px; margin: 10px 0;">
              🔗 This transaction hash proves the file was securely recorded on the blockchain.
            </p>
          </div>

          <div style="background-color: #f9fafb; padding: 20px; border-radius: 8px; border: 1px solid #e5e7eb; margin: 20px 0;">
            <h3 style="color: #374151; margin-top: 0;">📋 Next Steps</h3>
            <ol style="color: #4b5563; font-size: 14px; line-height: 1.6;">
              <li>Save the encryption key in a secure location</li>
              <li>Wait for the unlock time: <strong>${unlockTime}</strong></li>
              <li>Visit your SecureChain dashboard to access the file</li>
              <li>Enter the key when prompted to decrypt and download</li>
            </ol>
          </div>

          <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
            <p style="color: #6b7280; font-size: 12px; margin: 0;">
              Powered by SecureChain - Blockchain-based secure file sharing
            </p>
          </div>
        </div>
      </div>
    `;

    // Send email
    console.log('Attempting to send email to:', recipientUser.email);
    console.log('Email configuration check:', {
      user: process.env.EMAIL_USER ? 'Set' : 'Missing',
      pass: process.env.EMAIL_PASS ? 'Set' : 'Missing'
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: recipientUser.email,
      subject: `Secure File Shared: ${fileName}`,
      html: emailContent
    });

    console.log('Email sent successfully to:', recipientUser.email);
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
