// backend/src/models/Registration.js
const mongoose = require('mongoose');

const participantSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  rollNumber: {
    type: String,
    required: true,
    uppercase: true,
    trim: true
  },
  isIEEEMember: {
    type: Boolean,
    default: false
  },
  ieeeMembershipNumber: {
    type: String,
    trim: true
  },
  branch: {
    type: String,
    required: true,
    enum: ['CSE', 'ECE', 'EEE', 'IT', 'MECH', 'CIVIL', 'AIDS', 'CSBS', 'CSD']
  },
  mobileNumber: {
    type: String,
    required: true,
    match: [/^[6-9]\d{9}$/, 'Please enter a valid Indian mobile number']
  }
});

const registrationSchema = new mongoose.Schema({
  // Team Details
  teamName: {
    type: String,
    required: true,
    trim: true
  },
  collegeName: {
    type: String,
    trim: true
  },
  problemStatement: {
    type: String,
    required: true,
    trim: true
  },
  numberOfParticipants: {
    type: Number,
    required: true,
    enum: [1, 2, 3]
  },

  // Team Leader Info (Member 1)
  teamLeader: {
    type: participantSchema,
    required: true
  },

  // Member 2 (optional)
  member2: {
    type: participantSchema
  },
  // Member 3 (optional)
  member3: {
    type: participantSchema
  },

  // Additional Info
  // Additional Info
  contactMobile: {
    type: String,
    required: true,
    trim: true,
    match: [/^[6-9]\d{9}$/, 'Please enter a valid Indian mobile number']
  },
  projectFile: {
    originalName: {
      type: String,
      trim: true
    },
    fileName: {
      type: String,
      trim: true
    },
    mimeType: {
      type: String,
      trim: true
    },
    size: {
      type: Number
    },
    url: {
      type: String,
      trim: true
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    },
    storageProvider: {
      type: String,
      enum: ['local', 'cloudinary'],
      default: 'local'
    },
    cloudPublicId: {
      type: String,
      trim: true
    }
  },

  // College Details
  year: {
    type: String,
    required: true,
    enum: ['1st Year', '2nd Year', '3rd Year', '4th Year']
  },
  department: {
    type: String,
    required: true,
    enum: ['CSE', 'ECE', 'EEE', 'IT', 'MECH', 'CIVIL', 'AIDS', 'CSBS', 'CSD', 'OTHERS']
  },

  // Metadata
  registrationId: {
    type: String,
    unique: true,
    default: () => `AURION-${Date.now()}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  adminNote: {
    type: String,
    trim: true,
    maxlength: 500
  },
  statusUpdatedAt: {
    type: Date
  },
  submissionDate: {
    type: Date,
    default: Date.now
  },
  participantUpdateCount: {
    type: Number,
    default: 0
  },
  lastParticipantUpdateAt: {
    type: Date
  },
  ipAddress: String,
  userAgent: String
});

// Indexes for performance and uniqueness
registrationSchema.index({ 'teamLeader.email': 1 }, { unique: true, partialFilterExpression: { 'teamLeader.email': { $exists: true } } });
registrationSchema.index({ 'teamLeader.rollNumber': 1 }, { unique: true });
registrationSchema.index({ 'member2.email': 1 }, { unique: true, sparse: true });
registrationSchema.index({ 'member2.rollNumber': 1 }, { unique: true, sparse: true });
registrationSchema.index({ 'member3.email': 1 }, { unique: true, sparse: true });
registrationSchema.index({ 'member3.rollNumber': 1 }, { unique: true, sparse: true });
registrationSchema.index({ status: 1, submissionDate: -1 });
registrationSchema.index({ contactMobile: 1, submissionDate: -1 });
registrationSchema.index({ teamName: 1, submissionDate: -1 });
registrationSchema.index({ registrationId: 1, contactMobile: 1 });

const Registration = mongoose.model('Registration', registrationSchema);
module.exports = Registration;
