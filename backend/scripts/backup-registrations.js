require('dotenv').config();
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const Registration = require('../src/models/Registration');

// Improve SRV lookup reliability on networks with broken DNS resolvers.
dns.setServers(['8.8.8.8', '8.8.4.4']);

const toSafeTimestamp = (date) => date.toISOString().replace(/[:.]/g, '-');

const csvEscape = (value) => {
    if (value === null || value === undefined) return '""';
    const stringValue = String(value).replace(/"/g, '""');
    return `"${stringValue}"`;
};

const flattenRegistration = (reg) => ({
    registrationId: reg.registrationId || '',
    teamName: reg.teamName || '',
    problemStatement: reg.problemStatement || '',
    department: reg.department || '',
    year: reg.year || '',
    numberOfParticipants: reg.numberOfParticipants || 0,
    status: reg.status || '',
    adminNote: reg.adminNote || '',
    submissionDate: reg.submissionDate ? new Date(reg.submissionDate).toISOString() : '',
    statusUpdatedAt: reg.statusUpdatedAt ? new Date(reg.statusUpdatedAt).toISOString() : '',
    projectFileOriginalName: reg.projectFile?.originalName || '',
    projectFileName: reg.projectFile?.fileName || '',
    projectFileUrl: reg.projectFile?.url || '',
    projectFileStorage: reg.projectFile?.storageProvider || '',
    projectFileCloudPublicId: reg.projectFile?.cloudPublicId || '',
    contactMobile: reg.contactMobile || '',
    teamLeaderName: reg.teamLeader?.name || '',
    teamLeaderEmail: reg.teamLeader?.email || '',
    teamLeaderRollNumber: reg.teamLeader?.rollNumber || '',
    teamLeaderBranch: reg.teamLeader?.branch || '',
    teamLeaderMobile: reg.teamLeader?.mobileNumber || '',
    member2Name: reg.member2?.name || '',
    member2Email: reg.member2?.email || '',
    member2RollNumber: reg.member2?.rollNumber || '',
    member2Branch: reg.member2?.branch || '',
    member2Mobile: reg.member2?.mobileNumber || '',
    member3Name: reg.member3?.name || '',
    member3Email: reg.member3?.email || '',
    member3RollNumber: reg.member3?.rollNumber || '',
    member3Branch: reg.member3?.branch || '',
    member3Mobile: reg.member3?.mobileNumber || '',
    participantUpdateCount: reg.participantUpdateCount || 0,
    lastParticipantUpdateAt: reg.lastParticipantUpdateAt ? new Date(reg.lastParticipantUpdateAt).toISOString() : '',
    ipAddress: reg.ipAddress || '',
    userAgent: reg.userAgent || ''
  });

const buildCsv = (records) => {
    const rows = records.map(flattenRegistration);
    const headers = Object.keys(rows[0] || flattenRegistration({}));
    const lines = [headers.map(csvEscape).join(',')];

    rows.forEach(row => {
        lines.push(headers.map(header => csvEscape(row[header])).join(','));
    });

    return lines.join('\n');
};

async function runBackup() {
    const now = new Date();
    const timestamp = toSafeTimestamp(now);
    const backupDir = path.join(__dirname, '..', 'data', 'backups');
    const jsonFilePath = path.join(backupDir, `registrations-${timestamp}.json`);
    const csvFilePath = path.join(backupDir, `registrations-${timestamp}.csv`);

    fs.mkdirSync(backupDir, { recursive: true });

    await mongoose.connect(process.env.MONGODB_URI);
    const registrations = await Registration.find()
        .sort({ submissionDate: -1 })
        .lean();

    const payload = {
        generatedAt: now.toISOString(),
        total: registrations.length,
        registrations
    };

    fs.writeFileSync(jsonFilePath, JSON.stringify(payload, null, 2), 'utf8');
    fs.writeFileSync(csvFilePath, buildCsv(registrations), 'utf8');

    console.log(`Backup complete: ${registrations.length} registrations exported.`);
    console.log(`JSON: ${jsonFilePath}`);
    console.log(`CSV : ${csvFilePath}`);
}

runBackup()
    .catch((error) => {
        console.error('Backup failed:', error.message);
        process.exitCode = 1;
    })
    .finally(async () => {
        try {
            await mongoose.disconnect();
        } catch (_) {
            // Ignore disconnect errors in shutdown path.
        }
    });
