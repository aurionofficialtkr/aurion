// backend/src/server.js
require('dotenv').config({ override: true });
const express = require('express');
const dns = require('dns');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xlsx = require('xlsx');
const nodemailer = require('nodemailer');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { body, validationResult } = require('express-validator');
const fs = require('fs');
const path = require('path');

// Force reliable DNS for MongoDB SRV lookups on networks with broken resolvers
dns.setServers(['8.8.8.8', '8.8.4.4']);

const app = express();

console.log('Server starting...');
console.log('Admin credentials configured:', Boolean(process.env.ADMIN_ID && process.env.ADMIN_PASSWORD));

// Global Request Logger
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

if (!process.env.ADMIN_ID || !process.env.ADMIN_PASSWORD) {
    console.error('CRITICAL: ADMIN_ID or ADMIN_PASSWORD is missing in environment variables!');
}

// Middleware
app.use(helmet({
    // Frontend pages use inline scripts/styles and CDN assets (Tailwind/Google Fonts).
    // Disable default CSP here; add a strict custom CSP later for production.
    contentSecurityPolicy: false
}));
app.use(cors({
    origin: '*', // Allow all origins for dev
    methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const parsePositiveInt = (value, fallback) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
};

// Rate limiting
const limiter = rateLimit({
    windowMs: parsePositiveInt(process.env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    max: parsePositiveInt(process.env.RATE_LIMIT_MAX, 500), // Increased default for campus/shared networks
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', limiter);

// Database connection
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
    console.error('CRITICAL: MONGODB_URI is missing. API will start, but database features will not work.');
} else {
    mongoose.connect(mongoUri)
        .then(() => console.log('MongoDB Connected Successfully'))
        .catch(err => {
            console.error('MongoDB Connection Failed:', err);
        });
}

const Registration = require('./models/Registration');

const DB_READY_STATES = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
};

const normalizeRoll = value => String(value || '').trim().toUpperCase();
const normalizeEmail = value => String(value || '').trim().toLowerCase();
const normalizeMobile = value => String(value || '').trim();
const normalizeTeamName = value => String(value || '').trim().toLowerCase();
const deleteUploadedFile = filePath => {
    if (!filePath) return;
    fs.unlink(filePath, () => { });
};

const parseBoolean = (value, fallback = false) => {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
        const normalized = value.trim().toLowerCase();
        if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
        if (['false', '0', 'no', 'off'].includes(normalized)) return false;
    }
    return fallback;
};

const escapeRegex = (value = '') => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const getDbHealth = () => ({
    state: mongoose.connection.readyState,
    status: DB_READY_STATES[mongoose.connection.readyState] || 'unknown',
    name: mongoose.connection.name || null,
    host: mongoose.connection.host || null
});

const getDuplicateKeyInfo = (error) => {
    const keyPattern = error?.keyPattern || {};
    const keyValue = error?.keyValue || {};
    const field = Object.keys(keyPattern)[0] || Object.keys(keyValue)[0] || null;
    const value = field ? keyValue[field] : null;
    return { field, value };
};

const getDuplicateDetailsFromRegistration = (registrationDoc, incomingRolls, incomingEmails) => {
    const duplicateRolls = new Set();
    const duplicateEmails = new Set();
    const members = [registrationDoc.teamLeader, registrationDoc.member2, registrationDoc.member3].filter(Boolean);

    members.forEach(member => {
        const roll = normalizeRoll(member?.rollNumber);
        const email = normalizeEmail(member?.email);
        if (roll && incomingRolls.includes(roll)) duplicateRolls.add(roll);
        if (email && incomingEmails.includes(email)) duplicateEmails.add(email);
    });

    return {
        duplicateRolls: Array.from(duplicateRolls),
        duplicateEmails: Array.from(duplicateEmails)
    };
};

const buildDuplicateConflictReasons = ({
    duplicateTeamName = false,
    duplicateContactMobile = false,
    duplicateRolls = [],
    duplicateEmails = []
} = {}) => {
    const reasons = [];
    if (duplicateTeamName) reasons.push('Team name is already taken.');
    if (duplicateContactMobile) reasons.push('Contact mobile is already registered.');
    if (duplicateRolls.length) reasons.push(`Roll number already registered: ${duplicateRolls.join(', ')}.`);
    if (duplicateEmails.length) reasons.push(`Email already registered: ${duplicateEmails.join(', ')}.`);
    return reasons;
};

const uploadsRoot = path.join(__dirname, '..', 'uploads');
const registrationUploadDir = path.join(uploadsRoot, 'registrations');
fs.mkdirSync(registrationUploadDir, { recursive: true });

app.use('/uploads', express.static(uploadsRoot));

const cloudinaryEnabled =
    Boolean(process.env.CLOUDINARY_CLOUD_NAME) &&
    Boolean(process.env.CLOUDINARY_API_KEY) &&
    Boolean(process.env.CLOUDINARY_API_SECRET);

if (cloudinaryEnabled) {
    cloudinary.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET
    });
    console.log('Cloudinary storage enabled for project uploads.');
} else {
    console.log('Cloudinary not configured. Using local disk for project uploads.');
}

const allowedUploadExtensions = new Set(['.pdf', '.ppt', '.pptx']);
const allowedUploadMimeTypes = new Set([
    'application/pdf',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation'
]);

const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, registrationUploadDir),
    filename: (_req, file, cb) => {
        const ext = path.extname(file.originalname || '').toLowerCase();
        const safeBaseName = path.basename(file.originalname || 'project-file', ext)
            .replace(/[^a-zA-Z0-9_-]/g, '-')
            .slice(0, 40) || 'project-file';
        cb(null, `${Date.now()}-${safeBaseName}${ext}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (_req, file, cb) => {
        const ext = path.extname(file.originalname || '').toLowerCase();
        if (!allowedUploadExtensions.has(ext)) {
            cb(new Error('Only PDF, PPT, or PPTX files are allowed.'));
            return;
        }
        if (file.mimetype && !allowedUploadMimeTypes.has(file.mimetype)) {
            cb(new Error('Invalid file type. Please upload a valid PDF, PPT, or PPTX file.'));
            return;
        }
        cb(null, true);
    }
});

const uploadProjectFile = (req, res, next) => {
    upload.single('projectFile')(req, res, (err) => {
        if (!err) return next();
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File is too large. Maximum size is 10 MB.' });
        }
        return res.status(400).json({ error: err.message || 'File upload failed.' });
    });
};

const parseRegistrationPayload = (req, res, next) => {
    try {
        if (!req.body?.payload) {
            if (req.file?.path) deleteUploadedFile(req.file.path);
            return res.status(400).json({ error: 'Missing registration payload.' });
        }
        req.body = JSON.parse(req.body.payload);
        return next();
    } catch (error) {
        if (req.file?.path) deleteUploadedFile(req.file.path);
        return res.status(400).json({ error: 'Invalid registration payload format.' });
    }
};

const cloudinaryUploadFolder = process.env.CLOUDINARY_UPLOAD_FOLDER || 'aurion/registrations';
const registrationEnabled = parseBoolean(process.env.REGISTRATION_ENABLED, true);
const registrationMaxTeams = parsePositiveInt(process.env.REGISTRATION_MAX_TEAMS, 0);
const participantUpdateLimit = parsePositiveInt(process.env.PARTICIPANT_UPDATE_LIMIT, 1);
const registrationStartAt = process.env.REGISTRATION_START_AT ? new Date(process.env.REGISTRATION_START_AT) : null;
const registrationEndAt = process.env.REGISTRATION_END_AT ? new Date(process.env.REGISTRATION_END_AT) : null;

const isValidDate = (value) => value instanceof Date && !Number.isNaN(value.getTime());
const toValidDate = (value) => (isValidDate(value) ? value : null);
const configuredRegistrationStartAt = toValidDate(registrationStartAt);
const configuredRegistrationEndAt = toValidDate(registrationEndAt);

const generateRegistrationId = () => `AU-${Math.random().toString(36).slice(2, 11).toUpperCase()}`;

const getParticipantsFromPayload = (payload = {}) => [payload.teamLeader, payload.member2, payload.member3].filter(Boolean);

const getIncomingRollsAndEmails = (payload = {}) => {
    const participants = getParticipantsFromPayload(payload);
    return {
        rolls: participants.map(member => normalizeRoll(member?.rollNumber)).filter(Boolean),
        emails: participants.map(member => normalizeEmail(member?.email)).filter(Boolean)
    };
};

const getRegistrationWindowState = async () => {
    const now = new Date();
    const totalRegisteredTeams = await Registration.estimatedDocumentCount();
    const maxTeams = registrationMaxTeams > 0 ? registrationMaxTeams : null;
    const reachedLimit = Boolean(maxTeams && totalRegisteredTeams >= maxTeams);
    const hasStarted = !configuredRegistrationStartAt || now >= configuredRegistrationStartAt;
    const withinEnd = !configuredRegistrationEndAt || now <= configuredRegistrationEndAt;
    const isOpen = registrationEnabled && hasStarted && withinEnd && !reachedLimit;

    let reason = null;
    if (!registrationEnabled) reason = 'Registration is currently closed by admin.';
    else if (!hasStarted) reason = `Registration opens on ${configuredRegistrationStartAt.toISOString()}.`;
    else if (!withinEnd) reason = `Registration closed on ${configuredRegistrationEndAt.toISOString()}.`;
    else if (reachedLimit) reason = `Registration limit reached (${maxTeams} teams).`;

    return {
        isOpen,
        reason,
        totalRegisteredTeams,
        maxTeams,
        remainingSlots: maxTeams ? Math.max(maxTeams - totalRegisteredTeams, 0) : null,
        startsAt: configuredRegistrationStartAt,
        endsAt: configuredRegistrationEndAt
    };
};

const buildRegistrationSearchQuery = ({ rolls = [], emails = [], teamName = '', contactMobile = '', excludeId = null } = {}) => {
    const orConditions = [];
    if (rolls.length) {
        orConditions.push(
            { 'teamLeader.rollNumber': { $in: rolls } },
            { 'member2.rollNumber': { $in: rolls } },
            { 'member3.rollNumber': { $in: rolls } }
        );
    }
    if (emails.length) {
        orConditions.push(
            { 'teamLeader.email': { $in: emails } },
            { 'member2.email': { $in: emails } },
            { 'member3.email': { $in: emails } }
        );
    }
    if (teamName) {
        orConditions.push({ teamName: { $regex: `^${escapeRegex(teamName)}$`, $options: 'i' } });
    }
    if (contactMobile) {
        orConditions.push({ contactMobile });
    }

    const query = orConditions.length ? { $or: orConditions } : {};
    if (excludeId) query.registrationId = { $ne: excludeId };
    return query;
};

const storeProjectFile = async (file) => {
    if (!file) return undefined;

    if (cloudinaryEnabled) {
        const uploaded = await cloudinary.uploader.upload(file.path, {
            resource_type: 'raw',
            folder: cloudinaryUploadFolder,
            use_filename: true,
            unique_filename: true
        });
        deleteUploadedFile(file.path);

        return {
            originalName: file.originalname,
            fileName: file.filename,
            mimeType: file.mimetype,
            size: file.size,
            url: uploaded.secure_url,
            uploadedAt: new Date(),
            storageProvider: 'cloudinary',
            cloudPublicId: uploaded.public_id
        };
    }

    return {
        originalName: file.originalname,
        fileName: file.filename,
        mimeType: file.mimetype,
        size: file.size,
        url: `/uploads/registrations/${file.filename}`,
        uploadedAt: new Date(),
        storageProvider: 'local'
    };
};

const deleteCloudinaryFile = async (publicId) => {
    if (!publicId || !cloudinaryEnabled) return;
    try {
        await cloudinary.uploader.destroy(publicId, { resource_type: 'raw' });
    } catch (err) {
        console.error('Cloudinary cleanup failed:', err.message);
    }
};

const buildCloudinaryDownloadUrl = (projectFile) => {
    if (!projectFile?.cloudPublicId || !cloudinaryEnabled) return null;
    const ext = path.extname(projectFile.originalName || '').replace('.', '');
    const hasExtInPublicId = projectFile.cloudPublicId.includes('.');
    return cloudinary.utils.private_download_url(
        projectFile.cloudPublicId,
        hasExtInPublicId ? '' : ext,
        {
            resource_type: 'raw',
            type: 'upload',
            expires_at: Math.floor(Date.now() / 1000) + 600
        }
    );
};

// Email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const canSendEmail = Boolean(process.env.EMAIL_USER && process.env.EMAIL_PASS);

const sendRegistrationConfirmationEmail = async (registration) => {
    if (!canSendEmail || !registration?.teamLeader?.email) return;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: registration.teamLeader.email,
        subject: `AURION Registration Confirmed - ${registration.registrationId}`,
        text: [
            `Hello ${registration.teamLeader.name || 'Participant'},`,
            '',
            'Your registration for AURION Hardware Project Expo is confirmed.',
            `Registration ID: ${registration.registrationId}`,
            `Team Name: ${registration.teamName}`,
            `Status: ${registration.status}`,
            '',
            'Keep this Registration ID for future status checks and updates.',
            '',
            'Regards,',
            'AURION Organizing Team'
        ].join('\n')
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error('Registration confirmation email failed:', error.message);
    }
};

const sendStatusUpdateEmail = async (registration) => {
    if (!canSendEmail || !registration?.teamLeader?.email) return;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: registration.teamLeader.email,
        subject: `AURION Registration Status Updated - ${registration.registrationId}`,
        text: [
            `Hello ${registration.teamLeader.name || 'Participant'},`,
            '',
            `Your registration status is now: ${registration.status.toUpperCase()}`,
            `Registration ID: ${registration.registrationId}`,
            registration.adminNote ? `Organizer Note: ${registration.adminNote}` : '',
            '',
            'Regards,',
            'AURION Organizing Team'
        ].filter(Boolean).join('\n')
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error('Status update email failed:', error.message);
    }
};

// Validation middleware
const validateRegistration = [
    body('teamName').notEmpty().trim().escape(),
    body('collegeName').notEmpty().trim().escape(),
    body('problemStatement').notEmpty().trim().escape(),
    body('numberOfParticipants').isIn([1, 2, 3]),
    body('year').isIn(['1st Year', '2nd Year', '3rd Year', '4th Year']),
    body('department').isIn(['CSE', 'ECE', 'EEE', 'IT', 'MECH', 'CIVIL', 'AIDS', 'CSBS', 'CSD', 'OTHERS']),
    body('teamLeader.name').notEmpty().trim().escape(),
    body('teamLeader.email').isEmail().normalizeEmail(),
    body('teamLeader.rollNumber').notEmpty().trim(),
    body('teamLeader.branch').notEmpty().trim(),
    body('teamLeader.mobileNumber').trim().matches(/^[6-9]\d{9}$/).withMessage('Invalid Mobile Number (10 digits required)'),
    body('contactMobile').trim().matches(/^[6-9]\d{9}$/).withMessage('Invalid Contact Mobile'),
    body().custom((_, { req }) => {
        if (!req.file) {
            throw new Error('Project file is required (PDF/PPT/PPTX).');
        }
        return true;
    }),
    body().custom((_, { req }) => {
        const count = Number(req.body.numberOfParticipants);
        const requiredFields = ['name', 'email', 'rollNumber', 'branch', 'mobileNumber'];

        const validateMember = (member, label) => {
            if (!member) throw new Error(`${label} details are required.`);
            for (const field of requiredFields) {
                if (!member[field]) throw new Error(`${label} ${field} is required.`);
            }
        };

        if (count >= 2) validateMember(req.body.member2, 'Member 2');
        if (count === 3) validateMember(req.body.member3, 'Member 3');

        const rollNumbers = [
            req.body.teamLeader?.rollNumber,
            req.body.member2?.rollNumber,
            req.body.member3?.rollNumber
        ]
            .filter(Boolean)
            .map(r => String(r).trim().toUpperCase());

        if (new Set(rollNumbers).size !== rollNumbers.length) {
            throw new Error('Roll numbers must be unique within the same team.');
        }

        const emails = [
            req.body.teamLeader?.email,
            req.body.member2?.email,
            req.body.member3?.email
        ]
            .filter(Boolean)
            .map(e => String(e).trim().toLowerCase());

        if (new Set(emails).size !== emails.length) {
            throw new Error('Emails must be unique within the same team.');
        }

        return true;
    })
];

// API Routes

// 1. Registration Endpoint
app.post('/api/register', uploadProjectFile, parseRegistrationPayload, validateRegistration, async (req, res) => {
    let storedProjectFile = null;
    try {
        console.log('Received registration request:', req.body);

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('Validation errors:', errors.array());
            if (req.file?.path) deleteUploadedFile(req.file.path);
            return res.status(400).json({ errors: errors.array() });
        }

        const registrationWindow = await getRegistrationWindowState();
        if (!registrationWindow.isOpen) {
            if (req.file?.path) deleteUploadedFile(req.file.path);
            const statusCode = registrationWindow.maxTeams && registrationWindow.remainingSlots === 0 ? 409 : 403;
            return res.status(statusCode).json({
                error: registrationWindow.reason || 'Registration is currently closed.',
                registrationWindow
            });
        }

        const { rolls: incomingRolls, emails: incomingEmails } = getIncomingRollsAndEmails(req.body);
        const normalizedTeam = normalizeTeamName(req.body.teamName);
        const normalizedContactMobile = normalizeMobile(req.body.contactMobile);

        const duplicateQuery = buildRegistrationSearchQuery({
            rolls: incomingRolls,
            emails: incomingEmails,
            teamName: normalizedTeam,
            contactMobile: normalizedContactMobile
        });

        const existingRegistration = await Registration.findOne(duplicateQuery)
            .select('registrationId teamName contactMobile teamLeader member2 member3');

        if (existingRegistration) {
            const duplicates = getDuplicateDetailsFromRegistration(existingRegistration, incomingRolls, incomingEmails);
            const duplicateTeamName =
                normalizeTeamName(existingRegistration.teamName) === normalizedTeam && Boolean(normalizedTeam);
            const duplicateContactMobile =
                normalizeMobile(existingRegistration.contactMobile) === normalizedContactMobile && Boolean(normalizedContactMobile);
            const duplicateSummary = {
                ...duplicates,
                duplicateTeamName,
                duplicateContactMobile
            };
            const conflictReasons = buildDuplicateConflictReasons(duplicateSummary);

            console.log('Duplicate registration found');
            if (req.file?.path) deleteUploadedFile(req.file.path);
            return res.status(409).json({
                error: conflictReasons[0] || 'Duplicate registration found. Team name, contact mobile, roll number, or email already exists.',
                registrationId: existingRegistration.registrationId,
                duplicates: duplicateSummary,
                conflictReasons
            });
        }

        storedProjectFile = await storeProjectFile(req.file);

        const registrationData = {
            ...req.body,
            registrationId: generateRegistrationId(),
            submissionDate: new Date(),
            status: 'pending',
            statusUpdatedAt: new Date(),
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            projectFile: storedProjectFile || undefined
        };

        if (!registrationData.teamLeader.isIEEEMember) {
            registrationData.teamLeader.ieeeMembershipNumber = undefined;
        }
        if (registrationData.member2 && !registrationData.member2.isIEEEMember) {
            registrationData.member2.ieeeMembershipNumber = undefined;
        }
        if (registrationData.member3 && !registrationData.member3.isIEEEMember) {
            registrationData.member3.ieeeMembershipNumber = undefined;
        }

        console.log('Saving new registration to MongoDB...');
        let savedRegistration = null;
        for (let attempt = 0; attempt < 3; attempt += 1) {
            try {
                if (attempt > 0) registrationData.registrationId = generateRegistrationId();
                savedRegistration = await Registration.create(registrationData);
                break;
            } catch (error) {
                const isRegistrationIdCollision =
                    error?.code === 11000 &&
                    (error?.keyPattern?.registrationId || error?.keyValue?.registrationId);
                if (!isRegistrationIdCollision || attempt === 2) throw error;
            }
        }

        console.log('Data saved successfully.');

        await sendRegistrationConfirmationEmail(savedRegistration);

        res.status(201).json({
            success: true,
            registrationId: savedRegistration.registrationId,
            projectFileUrl: savedRegistration.projectFile?.url || null,
            message: 'Registration successful! Confirmation email sent (if email is configured).',
            registrationWindow: await getRegistrationWindowState()
        });

    } catch (error) {
        console.error('Registration error details:', error);
        if (error?.code === 11000) {
            if (req.file?.path) deleteUploadedFile(req.file.path);
            if (storedProjectFile?.storageProvider === 'cloudinary') {
                await deleteCloudinaryFile(storedProjectFile.cloudPublicId);
            }
            const { field, value } = getDuplicateKeyInfo(error);
            let errorMessage = 'Duplicate registration found. This data is already registered.';
            if (field?.toLowerCase().includes('rollnumber')) {
                errorMessage = 'Duplicate registration found. Roll number already registered.';
            } else if (field?.toLowerCase().includes('email')) {
                errorMessage = 'Duplicate registration found. Email already registered.';
            }
            return res.status(409).json({ error: errorMessage, field, value });
        }
        if (req.file?.path) deleteUploadedFile(req.file.path);
        if (storedProjectFile?.storageProvider === 'cloudinary') {
            await deleteCloudinaryFile(storedProjectFile.cloudPublicId);
        }
        res.status(500).json({ error: 'Internal server error: ' + error.message });
    }
});

const allowedYears = new Set(['1st Year', '2nd Year', '3rd Year', '4th Year']);
const allowedDepartments = new Set(['CSE', 'ECE', 'EEE', 'IT', 'MECH', 'CIVIL', 'AIDS', 'CSBS', 'CSD', 'OTHERS']);
const allowedBranches = new Set(['CSE', 'ECE', 'EEE', 'IT', 'MECH', 'CIVIL', 'AIDS', 'CSBS', 'CSD']);
const mobileRegex = /^[6-9]\d{9}$/;
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const sanitizeParticipant = (member = {}) => ({
    name: String(member.name || '').trim(),
    email: normalizeEmail(member.email),
    rollNumber: normalizeRoll(member.rollNumber),
    branch: String(member.branch || '').trim().toUpperCase(),
    mobileNumber: normalizeMobile(member.mobileNumber),
    isIEEEMember: Boolean(member.isIEEEMember),
    ieeeMembershipNumber: member.isIEEEMember ? String(member.ieeeMembershipNumber || '').trim() : undefined
});

const validateParticipant = (member, label, errors) => {
    if (!member) {
        errors.push(`${label} details are required.`);
        return;
    }

    if (!member.name) errors.push(`${label} name is required.`);
    if (!emailRegex.test(member.email || '')) errors.push(`${label} email is invalid.`);
    if (!member.rollNumber) errors.push(`${label} roll number is required.`);
    if (!allowedBranches.has(member.branch)) errors.push(`${label} branch is invalid.`);
    if (!mobileRegex.test(member.mobileNumber || '')) errors.push(`${label} mobile number is invalid.`);
    if (member.isIEEEMember && !member.ieeeMembershipNumber) {
        errors.push(`${label} IEEE membership number is required when marked as IEEE member.`);
    }
};

const buildMergedRegistrationPayload = (existing, incoming = {}) => {
    const merged = {
        teamName: String(incoming.teamName ?? existing.teamName ?? '').trim(),
        problemStatement: String(incoming.problemStatement ?? existing.problemStatement ?? '').trim(),
        numberOfParticipants: Number(incoming.numberOfParticipants ?? existing.numberOfParticipants),
        year: String(incoming.year ?? existing.year ?? '').trim(),
        department: String(incoming.department ?? existing.department ?? '').trim().toUpperCase(),
        contactMobile: normalizeMobile(incoming.contactMobile ?? existing.contactMobile),
        teamLeader: sanitizeParticipant(incoming.teamLeader ?? existing.teamLeader),
        member2: sanitizeParticipant(incoming.member2 ?? existing.member2),
        member3: sanitizeParticipant(incoming.member3 ?? existing.member3)
    };

    if (merged.numberOfParticipants < 2) merged.member2 = undefined;
    if (merged.numberOfParticipants < 3) merged.member3 = undefined;

    return merged;
};

const validateMergedPayload = (payload) => {
    const errors = [];

    if (!payload.teamName) errors.push('Team name is required.');
    if (!payload.problemStatement) errors.push('Problem statement is required.');
    if (![1, 2, 3].includes(payload.numberOfParticipants)) {
        errors.push('Number of participants must be 1, 2, or 3.');
    }
    if (!allowedYears.has(payload.year)) errors.push('Year is invalid.');
    if (!allowedDepartments.has(payload.department)) errors.push('Department is invalid.');
    if (!mobileRegex.test(payload.contactMobile || '')) errors.push('Contact mobile number is invalid.');

    validateParticipant(payload.teamLeader, 'Team Leader', errors);
    if (payload.numberOfParticipants >= 2) validateParticipant(payload.member2, 'Member 2', errors);
    if (payload.numberOfParticipants >= 3) validateParticipant(payload.member3, 'Member 3', errors);

    const rolls = [payload.teamLeader?.rollNumber, payload.member2?.rollNumber, payload.member3?.rollNumber]
        .filter(Boolean)
        .map(normalizeRoll);
    if (new Set(rolls).size !== rolls.length) errors.push('Roll numbers must be unique within the team.');

    const emails = [payload.teamLeader?.email, payload.member2?.email, payload.member3?.email]
        .filter(Boolean)
        .map(normalizeEmail);
    if (new Set(emails).size !== emails.length) errors.push('Emails must be unique within the team.');

    return errors;
};

// 2. Public - Registration open/slots config
app.get('/api/registration/config', async (_req, res) => {
    try {
        const registrationWindow = await getRegistrationWindowState();
        res.json({
            registrationWindow,
            participantUpdateLimit
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 3. Public - Team name availability check
app.get('/api/registrations/team-name-availability', async (req, res) => {
    try {
        const teamName = String(req.query?.teamName || '').trim();
        if (!teamName) {
            return res.status(400).json({ error: 'Team name is required.' });
        }

        const existing = await Registration.findOne({
            teamName: { $regex: `^${escapeRegex(teamName)}$`, $options: 'i' }
        }).select('registrationId teamName');

        if (!existing) {
            return res.json({ available: true });
        }

        return res.json({
            available: false,
            registrationId: existing.registrationId,
            teamName: existing.teamName
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// 4. Public - Participant status check by registration ID + contact mobile
app.post('/api/registrations/status-check', async (req, res) => {
    try {
        const registrationId = String(req.body?.registrationId || '').trim().toUpperCase();
        const contactMobile = normalizeMobile(req.body?.contactMobile);

        if (!registrationId || !mobileRegex.test(contactMobile)) {
            return res.status(400).json({ error: 'Registration ID and valid contact mobile are required.' });
        }

        const registration = await Registration.findOne({
            registrationId,
            contactMobile
        }).select('registrationId teamName status submissionDate statusUpdatedAt adminNote participantUpdateCount contactMobile');

        if (!registration) {
            return res.status(404).json({ error: 'No matching registration found for provided ID and mobile.' });
        }

        const updatesUsed = registration.participantUpdateCount || 0;
        const updatesRemaining = Math.max(participantUpdateLimit - updatesUsed, 0);

        res.json({
            success: true,
            registration: {
                registrationId: registration.registrationId,
                teamName: registration.teamName,
                status: registration.status,
                adminNote: registration.adminNote || '',
                submissionDate: registration.submissionDate,
                statusUpdatedAt: registration.statusUpdatedAt || registration.submissionDate
            },
            participantEdits: {
                limit: participantUpdateLimit,
                used: updatesUsed,
                remaining: updatesRemaining,
                canEdit: registration.status === 'pending' && updatesRemaining > 0
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 5. Public - Participant one-time update by registration ID + contact mobile
app.patch('/api/registrations/:id', async (req, res) => {
    try {
        const registrationId = String(req.params.id || '').trim().toUpperCase();
        const authMobile = normalizeMobile(req.body?.contactMobile);
        const incomingUpdates = req.body?.updates && typeof req.body.updates === 'object'
            ? req.body.updates
            : { ...req.body };

        if (!req.body?.updates && incomingUpdates.contactMobile) {
            delete incomingUpdates.contactMobile;
        }

        if (!registrationId || !mobileRegex.test(authMobile)) {
            return res.status(400).json({ error: 'Registration ID and valid contact mobile are required.' });
        }

        const registration = await Registration.findOne({ registrationId });
        if (!registration) {
            return res.status(404).json({ error: 'Registration not found.' });
        }
        if (normalizeMobile(registration.contactMobile) !== authMobile) {
            return res.status(403).json({ error: 'Contact mobile does not match this registration.' });
        }
        if (registration.status !== 'pending') {
            return res.status(409).json({ error: 'Registration can only be edited while status is pending.' });
        }
        if ((registration.participantUpdateCount || 0) >= participantUpdateLimit) {
            return res.status(409).json({ error: `Edit limit reached. Maximum allowed updates: ${participantUpdateLimit}.` });
        }

        const mergedPayload = buildMergedRegistrationPayload(registration.toObject(), incomingUpdates);
        const shapeErrors = validateMergedPayload(mergedPayload);
        if (shapeErrors.length) {
            return res.status(400).json({ error: 'Validation failed.', details: shapeErrors });
        }

        const incomingIdentity = getIncomingRollsAndEmails(mergedPayload);
        const duplicateQuery = buildRegistrationSearchQuery({
            rolls: incomingIdentity.rolls,
            emails: incomingIdentity.emails,
            teamName: normalizeTeamName(mergedPayload.teamName),
            contactMobile: normalizeMobile(mergedPayload.contactMobile),
            excludeId: registrationId
        });
        const duplicateRecord = await Registration.findOne(duplicateQuery)
            .select('registrationId teamName contactMobile teamLeader member2 member3');

        if (duplicateRecord) {
            const duplicates = getDuplicateDetailsFromRegistration(
                duplicateRecord,
                incomingIdentity.rolls,
                incomingIdentity.emails
            );
            const duplicateSummary = {
                ...duplicates,
                duplicateTeamName: normalizeTeamName(duplicateRecord.teamName) === normalizeTeamName(mergedPayload.teamName),
                duplicateContactMobile: normalizeMobile(duplicateRecord.contactMobile) === normalizeMobile(mergedPayload.contactMobile)
            };
            const conflictReasons = buildDuplicateConflictReasons(duplicateSummary);
            return res.status(409).json({
                error: conflictReasons[0] || 'Update conflicts with an existing registration.',
                registrationId: duplicateRecord.registrationId,
                duplicates: duplicateSummary,
                conflictReasons
            });
        }

        const updateData = {
            teamName: mergedPayload.teamName,
            problemStatement: mergedPayload.problemStatement,
            numberOfParticipants: mergedPayload.numberOfParticipants,
            year: mergedPayload.year,
            department: mergedPayload.department,
            contactMobile: mergedPayload.contactMobile,
            teamLeader: mergedPayload.teamLeader,
            participantUpdateCount: (registration.participantUpdateCount || 0) + 1,
            lastParticipantUpdateAt: new Date()
        };

        if (mergedPayload.numberOfParticipants >= 2) updateData.member2 = mergedPayload.member2;
        if (mergedPayload.numberOfParticipants === 3) updateData.member3 = mergedPayload.member3;

        const unsetData = {};
        if (mergedPayload.numberOfParticipants < 2) unsetData.member2 = '';
        if (mergedPayload.numberOfParticipants < 3) unsetData.member3 = '';

        const updatedRegistration = await Registration.findOneAndUpdate(
            { registrationId },
            {
                $set: updateData,
                ...(Object.keys(unsetData).length ? { $unset: unsetData } : {})
            },
            { new: true, runValidators: true }
        );

        res.json({
            success: true,
            message: 'Registration updated successfully.',
            registrationId: updatedRegistration.registrationId,
            participantEdits: {
                limit: participantUpdateLimit,
                used: updatedRegistration.participantUpdateCount,
                remaining: Math.max(participantUpdateLimit - updatedRegistration.participantUpdateCount, 0)
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 2. Admin Authentication Middleware
const authenticateAdmin = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return res.status(401).json({ error: 'Unauthorized: Missing Authorization Header' });
        }

        const parts = authHeader.split(' ');
        if (parts.length !== 2 || parts[0] !== 'Basic') {
            return res.status(401).json({ error: 'Unauthorized: Invalid Header Format' });
        }

        const credentials = Buffer.from(parts[1], 'base64').toString('ascii');
        const [id, password] = credentials.split(':');

        const expectedId = process.env.ADMIN_ID;
        const expectedPassword = process.env.ADMIN_PASSWORD;

        if (!id || !password || id !== expectedId || password !== expectedPassword) {
            return res.status(401).json({ error: 'Unauthorized: Invalid Credentials' });
        }

        next();
    } catch (err) {
        console.error('Auth Middleware Error:', err);
        res.status(500).json({ error: 'Internal Server Error during Authentication' });
    }
};

// 3. Admin - Get all registrations
app.get('/api/admin/registrations', authenticateAdmin, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 50,
            department,
            year,
            ieeeMember,
            status,
            search
        } = req.query;
        const pageNum = parsePositiveInt(page, 1);
        const limitNum = Math.min(parsePositiveInt(limit, 50), 500);

        // Build Query
        const query = {};
        if (department) query.department = department;
        if (year) query.year = year;
        if (status) query.status = status;
        if (ieeeMember === 'true') {
            query.$or = [
                { 'teamLeader.isIEEEMember': true },
                { 'member2.isIEEEMember': true },
                { 'member3.isIEEEMember': true }
            ];
        }

        if (search) {
            const regex = new RegExp(search, 'i');
            query.$or = [
                { teamName: regex },
                { collegeName: regex },
                { 'teamLeader.name': regex },
                { 'teamLeader.email': regex },
                { registrationId: regex }
            ];
        }

        // Execute Query with Pagination
        const total = await Registration.countDocuments(query);
        const registrations = await Registration.find(query)
            .sort({ submissionDate: -1 })
            .skip((pageNum - 1) * limitNum)
            .limit(limitNum);

        res.json({
            registrations,
            pagination: {
                total,
                page: pageNum,
                totalPages: Math.ceil(total / limitNum)
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 4. Admin - Download project file
app.get('/api/admin/registrations/:id/project-file', authenticateAdmin, async (req, res) => {
    try {
        const wantsJson = String(req.query?.format || '').toLowerCase() === 'json';
        const wantsProxy = String(req.query?.mode || '').toLowerCase() === 'proxy';
        const downloadMode = String(req.query?.download || '').toLowerCase() === '1';
        const registration = await Registration.findOne(
            { registrationId: req.params.id },
            { registrationId: 1, projectFile: 1 }
        );

        if (!registration) {
            return res.status(404).json({ error: 'Registration not found' });
        }

        if (!registration.projectFile?.url) {
            return res.status(404).json({ error: 'Project file not found' });
        }

        if (registration.projectFile.storageProvider === 'cloudinary') {
            const signedUrl = buildCloudinaryDownloadUrl(registration.projectFile);
            if (!signedUrl) {
                return res.status(500).json({ error: 'Cloud file access is not configured correctly.' });
            }
            if (wantsProxy) {
                const upstream = await fetch(signedUrl);
                if (!upstream.ok) {
                    return res.status(502).json({ error: 'Unable to fetch cloud file.' });
                }
                const fileBuffer = Buffer.from(await upstream.arrayBuffer());
                const contentType = registration.projectFile.mimeType || upstream.headers.get('content-type') || 'application/octet-stream';
                const fileName = registration.projectFile.originalName || registration.projectFile.fileName || 'project-file';
                const safeFileName = String(fileName).replace(/["\\\r\n]/g, '_');
                const disposition = downloadMode ? 'attachment' : 'inline';
                res.setHeader('Content-Type', contentType);
                res.setHeader('Content-Disposition', `${disposition}; filename="${safeFileName}"`);
                return res.send(fileBuffer);
            }
            if (wantsJson) {
                return res.json({
                    url: signedUrl,
                    fileName: registration.projectFile.originalName || registration.projectFile.fileName || 'project-file'
                });
            }
            return res.redirect(signedUrl);
        }

        const localPath = path.join(registrationUploadDir, registration.projectFile.fileName || '');
        if (!registration.projectFile.fileName || !fs.existsSync(localPath)) {
            return res.status(404).json({ error: 'Local project file not found' });
        }
        if (wantsProxy) {
            const fileBuffer = fs.readFileSync(localPath);
            const contentType = registration.projectFile.mimeType || 'application/octet-stream';
            const fileName = registration.projectFile.originalName || registration.projectFile.fileName || 'project-file';
            const safeFileName = String(fileName).replace(/["\\\r\n]/g, '_');
            const disposition = downloadMode ? 'attachment' : 'inline';
            res.setHeader('Content-Type', contentType);
            res.setHeader('Content-Disposition', `${disposition}; filename="${safeFileName}"`);
            return res.send(fileBuffer);
        }
        if (wantsJson) {
            return res.json({
                url: `/uploads/registrations/${registration.projectFile.fileName}`,
                fileName: registration.projectFile.originalName || registration.projectFile.fileName
            });
        }
        return res.download(localPath, registration.projectFile.originalName || registration.projectFile.fileName);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 5. Admin - Update registration status
app.patch('/api/admin/registrations/:id/status', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const adminNote = String(req.body?.adminNote || '').trim().slice(0, 500);
        if (!['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const updatedRegistration = await Registration.findOneAndUpdate(
            { registrationId: req.params.id },
            {
                status,
                adminNote: adminNote || undefined,
                statusUpdatedAt: new Date()
            },
            { new: true, runValidators: true }
        );

        if (!updatedRegistration) {
            return res.status(404).json({ error: 'Registration not found' });
        }

        await sendStatusUpdateEmail(updatedRegistration);
        res.json(updatedRegistration);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 6. Export to Excel
const buildRegistrationExportRows = (registrations = []) => registrations.map(reg => ({
    'Registration ID': reg.registrationId,
    'Team Name': reg.teamName,
    'College Name': reg.collegeName || 'N/A',
    'Problem Statement': reg.problemStatement,
    'Project File URL': reg.projectFile?.url || 'N/A',
    'Project File Storage': reg.projectFile?.storageProvider || 'N/A',
    'Status': reg.status,
    'Admin Note': reg.adminNote || 'N/A',
    'Submission Date': reg.submissionDate ? new Date(reg.submissionDate).toLocaleString('en-IN') : 'N/A',
    'Status Updated At': reg.statusUpdatedAt ? new Date(reg.statusUpdatedAt).toLocaleString('en-IN') : 'N/A',
    'Contact Mobile': reg.contactMobile,
    'Year': reg.year,
    'Department': reg.department,
    'No. of Participants': reg.numberOfParticipants,
    'Participant Update Count': reg.participantUpdateCount || 0,
    // Team Leader
    'TL Name': reg.teamLeader?.name || 'N/A',
    'TL Email': reg.teamLeader?.email || 'N/A',
    'TL Roll No': reg.teamLeader?.rollNumber || 'N/A',
    'TL IEEE Member': reg.teamLeader?.isIEEEMember ? 'Yes' : 'No',
    'TL IEEE No': reg.teamLeader?.ieeeMembershipNumber || 'N/A',
    'TL Branch': reg.teamLeader?.branch || 'N/A',
    'TL Mobile': reg.teamLeader?.mobileNumber || 'N/A',
    // Member 2
    'M2 Name': reg.member2?.name || 'N/A',
    'M2 Email': reg.member2?.email || 'N/A',
    'M2 Roll No': reg.member2?.rollNumber || 'N/A',
    'M2 IEEE Member': reg.member2?.isIEEEMember ? 'Yes' : 'No',
    'M2 IEEE No': reg.member2?.ieeeMembershipNumber || 'N/A',
    'M2 Branch': reg.member2?.branch || 'N/A',
    'M2 Mobile': reg.member2?.mobileNumber || 'N/A',
    // Member 3
    'M3 Name': reg.member3?.name || 'N/A',
    'M3 Email': reg.member3?.email || 'N/A',
    'M3 Roll No': reg.member3?.rollNumber || 'N/A',
    'M3 IEEE Member': reg.member3?.isIEEEMember ? 'Yes' : 'No',
    'M3 IEEE No': reg.member3?.ieeeMembershipNumber || 'N/A',
    'M3 Branch': reg.member3?.branch || 'N/A',
    'M3 Mobile': reg.member3?.mobileNumber || 'N/A'
}));

const buildWorkbookFromRows = (rows, sheetName = 'Registrations') => {
    const worksheet = xlsx.utils.json_to_sheet(rows);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, sheetName);

    worksheet['!cols'] = [
        { wch: 20 }, { wch: 25 }, { wch: 45 }, { wch: 45 }, { wch: 15 }, { wch: 12 }, { wch: 35 },
        { wch: 22 }, { wch: 22 }, { wch: 15 }, { wch: 10 }, { wch: 10 }, { wch: 8 }, { wch: 12 },
        { wch: 22 }, { wch: 28 }, { wch: 16 }, { wch: 10 }, { wch: 16 }, { wch: 12 }, { wch: 15 },
        { wch: 22 }, { wch: 28 }, { wch: 16 }, { wch: 10 }, { wch: 16 }, { wch: 12 }, { wch: 15 },
        { wch: 22 }, { wch: 28 }, { wch: 16 }, { wch: 10 }, { wch: 16 }, { wch: 12 }, { wch: 15 }
    ];

    return { workbook, worksheet };
};

const writeDailyRegistrationBackup = async () => {
    try {
        if (mongoose.connection.readyState !== 1) {
            console.log('Daily backup skipped: database not connected.');
            return;
        }

        const registrations = await Registration.find().sort({ submissionDate: -1 }).lean();
        const rows = buildRegistrationExportRows(registrations);
        const { workbook } = buildWorkbookFromRows(rows, 'Registrations');
        const xlsxBuffer = xlsx.write(workbook, { type: 'buffer', bookType: 'xlsx' });
        const csv = xlsx.utils.sheet_to_csv(xlsx.utils.json_to_sheet(rows));

        const backupDir = path.join(__dirname, '..', 'data', 'backups');
        fs.mkdirSync(backupDir, { recursive: true });

        const stamp = new Date().toISOString().split('T')[0];
        const xlsxPath = path.join(backupDir, `registrations-daily-${stamp}.xlsx`);
        const csvPath = path.join(backupDir, `registrations-daily-${stamp}.csv`);
        fs.writeFileSync(xlsxPath, xlsxBuffer);
        fs.writeFileSync(csvPath, csv, 'utf8');
        console.log(`Daily backup written: ${xlsxPath}`);
    } catch (error) {
        console.error('Daily backup failed:', error.message);
    }
};

const scheduleDailyBackup = () => {
    const now = new Date();
    const next = new Date(now);
    next.setHours(2, 0, 0, 0);
    if (next <= now) next.setDate(next.getDate() + 1);
    const delay = next.getTime() - now.getTime();

    setTimeout(() => {
        writeDailyRegistrationBackup();
        setInterval(writeDailyRegistrationBackup, 24 * 60 * 60 * 1000);
    }, delay);
};

app.get('/api/admin/export/excel', authenticateAdmin, async (req, res) => {
    try {
        const registrations = await Registration.find().sort({ submissionDate: -1 });
        const rows = buildRegistrationExportRows(registrations);
        const { workbook } = buildWorkbookFromRows(rows, 'Registrations');
        const buffer = xlsx.write(workbook, { type: 'buffer', bookType: 'xlsx' });

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename="aurion_registrations.xlsx"');
        res.send(buffer);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 7. Admin - Trigger backup now
app.post('/api/admin/backup/run', authenticateAdmin, async (_req, res) => {
    try {
        await writeDailyRegistrationBackup();
        res.json({ success: true, message: 'Backup generated successfully.' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 8. Admin - Database health
app.get('/api/admin/health', authenticateAdmin, async (req, res) => {
    try {
        const db = getDbHealth();
        const totalRegistrations = db.status === 'connected'
            ? await Registration.estimatedDocumentCount()
            : null;

        res.json({
            status: 'ok',
            timestamp: new Date(),
            db,
            totalRegistrations
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 9. Admin - Dashboard stats
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 6);
        sevenDaysAgo.setHours(0, 0, 0, 0);

        const [
            totalRegistrations,
            pendingCount,
            approvedCount,
            rejectedCount,
            ieeeTeamCount,
            totalParticipantCountAgg,
            departmentStats,
            yearStats,
            problemStatementStats,
            dailySubmissions
        ] = await Promise.all([
            Registration.countDocuments(),
            Registration.countDocuments({ status: 'pending' }),
            Registration.countDocuments({ status: 'approved' }),
            Registration.countDocuments({ status: 'rejected' }),
            Registration.countDocuments({
                $or: [
                    { 'teamLeader.isIEEEMember': true },
                    { 'member2.isIEEEMember': true },
                    { 'member3.isIEEEMember': true }
                ]
            }),
            Registration.aggregate([
                { $group: { _id: null, total: { $sum: '$numberOfParticipants' } } }
            ]),
            Registration.aggregate([
                { $group: { _id: '$department', count: { $sum: 1 } } },
                { $sort: { count: -1, _id: 1 } }
            ]),
            Registration.aggregate([
                { $group: { _id: '$year', count: { $sum: 1 } } },
                { $sort: { _id: 1 } }
            ]),
            Registration.aggregate([
                { $group: { _id: '$problemStatement', count: { $sum: 1 } } },
                { $sort: { count: -1, _id: 1 } },
                { $limit: 10 }
            ]),
            Registration.aggregate([
                { $match: { submissionDate: { $gte: sevenDaysAgo } } },
                {
                    $group: {
                        _id: {
                            $dateToString: { format: '%Y-%m-%d', date: '$submissionDate' }
                        },
                        count: { $sum: 1 }
                    }
                },
                { $sort: { _id: 1 } }
            ])
        ]);

        res.json({
            timestamp: new Date(),
            db: getDbHealth(),
            totals: {
                registrations: totalRegistrations,
                participants: totalParticipantCountAgg[0]?.total || 0,
                ieeeTeams: ieeeTeamCount
            },
            statusBreakdown: {
                pending: pendingCount,
                approved: approvedCount,
                rejected: rejectedCount
            },
            departmentBreakdown: departmentStats.map(item => ({ department: item._id, count: item.count })),
            yearBreakdown: yearStats.map(item => ({ year: item._id, count: item.count })),
            topProblemStatements: problemStatementStats.map(item => ({ problemStatement: item._id, count: item.count })),
            recentDailySubmissions: dailySubmissions.map(item => ({ date: item._id, count: item.count }))
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date(), db: getDbHealth() });
});

// Root API handler to prevent 404 confusion
app.get('/api', (req, res) => {
    res.json({
        message: 'AURION Event API is Running',
        endpoints: {
            register: 'POST /api/register',
            registrationConfig: 'GET /api/registration/config',
            teamNameAvailability: 'GET /api/registrations/team-name-availability?teamName=...',
            statusCheck: 'POST /api/registrations/status-check',
            registrationEdit: 'PATCH /api/registrations/:id',
            health: 'GET /api/health',
            adminHealth: 'GET /api/admin/health',
            adminStats: 'GET /api/admin/stats'
        }
    });
});

// Optional static hosting for frontend to simplify mobile access on same LAN.
const frontendStaticDir = path.join(__dirname, '..', '..', 'frontend');
if (fs.existsSync(frontendStaticDir)) {
    app.use(express.static(frontendStaticDir));
}

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () => {
    console.log(`Server running on ${HOST}:${PORT}`);
    writeDailyRegistrationBackup();
    scheduleDailyBackup();
});
