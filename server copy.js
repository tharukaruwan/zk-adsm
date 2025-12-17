const express = require("express");
const app = express();
const PORT = 8081;

// Parse JSON for API endpoints first
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Capture raw text for ZK protocol endpoints only (must use regex or specific routes)
app.use((req, res, next) => {
    if (req.path.startsWith('/iclock/')) {
        express.text({ type: "*/*" })(req, res, next);
    } else {
        next();
    }
});

// ---------------------------------------------------------
// DATABASE SIMULATION
// ---------------------------------------------------------
let devices = {};       
let commandQueue = {};
let commandResults = {}; // Track command execution results

const updateDeviceHealth = (sn) => {
    if (!sn) return;
    const now = new Date();
    devices[sn] = {
        lastSeen: now.toLocaleString(),
        status: "Online",
        timestamp: now.getTime()
    };
};

// ---------------------------------------------------------
// 1. REGISTRY HANDLER (Protocol Section 5)
// ---------------------------------------------------------
app.post("/iclock/registry", (req, res) => {
    const { SN } = req.query;
    console.log(`📝 Registry Request from SN: ${SN}`);
    updateDeviceHealth(SN);
    res.set("Content-Type", "text/plain");
    res.send("RegistryCode=OK\n"); 
});

// ---------------------------------------------------------
// 2. INITIALIZATION INFORMATION EXCHANGE (Protocol Section 5)
// ---------------------------------------------------------
app.get("/iclock/cdata", (req, res) => {
    const { SN, options } = req.query;
    updateDeviceHealth(SN);

    if (options === "all") {
        console.log(`⚙️  Configuration request from ${SN}`);
        const now = Math.floor(Date.now() / 1000);
        
        // Protocol Section 5 - Server Configuration
        const config = [
            `GET OPTION FROM: ${SN}`,
            `Stamp=${now}`,
            `OpStamp=${now}`,
            `ErrorDelay=30`,
            `Delay=10`,
            `TransInterval=1`,
            `TransFlag=TransData AttLog OpLog AttPhoto EnrollUser ChgUser`,
            `TimeZone=8`,
            `Realtime=1`,
            `Encrypt=0`,
            `ServerVer=3.4.1`,
            `PushProtVer=2.4.2`
        ].join("\r\n") + "\r\n";

        res.set("Content-Type", "text/plain");
        return res.send(config);
    }
    
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 3. DATA UPLOAD HANDLER (Protocol Section 11)
// ---------------------------------------------------------
app.post("/iclock/cdata", (req, res) => {
    const { SN, table } = req.query;
    updateDeviceHealth(SN);

    // Attendance Records (Protocol 11.2)
    if (table === "ATTLOG" || table === "rtlog") {
        const rawData = req.body ? req.body.trim() : "";
        const lines = rawData.split("\n");

        lines.forEach(line => {
            if (!line) return;
            const dataObj = {};
            line.split("\t").forEach(pair => {
                const [key, value] = pair.split("=");
                if (key && value) dataObj[key] = value;
            });
            console.log(`✅ [ATTENDANCE] User ${dataObj.PIN || '??'} at ${dataObj.Time || '??'}`);
        });
        
        res.set("Content-Type", "text/plain");
        return res.send(`OK: ${lines.length}\n`);
    }

    // User Information Upload (Protocol 11.5)
    if (table === "OPERLOG") {
        const rawData = req.body ? req.body.trim() : "";
        console.log(`📊 Operation Log: ${rawData}`);
        res.set("Content-Type", "text/plain");
        return res.send("OK: 1\n");
    }

    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 4. COMMAND POLLING (Protocol Section 12)
// ---------------------------------------------------------
app.get("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    
    console.log(`💓 Heartbeat from ${SN} at ${new Date().toLocaleTimeString()}`);
    
    res.set("Content-Type", "text/plain");

    if (commandQueue[SN] && commandQueue[SN].length > 0) {
        const cmd = commandQueue[SN].shift();
        console.log(`🚀 Sending Command to ${SN}:\n${cmd.replace(/\t/g, ' [TAB] ')}`);
        return res.send(cmd + "\n");
    }

    res.send("OK\n");
});

// ---------------------------------------------------------
// 5. COMMAND RESULT HANDLER (Protocol Section 13)
// ---------------------------------------------------------
app.post("/iclock/devicecmd", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    
    const result = req.body ? req.body.trim() : "";
    console.log(`🎯 Device ${SN} Command Result:\n${result}`);
    
    // Parse result
    const resultMatch = result.match(/ID=(\w+)&Return=(-?\d+)&CMD=(\w+)/);
    if (resultMatch) {
        const [, cmdId, returnCode, cmdType] = resultMatch;
        commandResults[cmdId] = {
            returnCode: parseInt(returnCode),
            cmdType,
            timestamp: new Date(),
            success: returnCode === "0"
        };
        
        if (returnCode === "0") {
            console.log(`✅ Command ${cmdId} executed successfully`);
        } else {
            console.log(`⚠️  Command ${cmdId} failed with code ${returnCode}`);
        }
    }
    
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 6. USER CRUD API ENDPOINTS (Protocol Section 12.1.1.1)
// ---------------------------------------------------------

/**
 * CREATE USER
 * Protocol: Section 12.1.1.1 - User Information
 * Format: C:${CmdID}:DATA UPDATE USERINFO PIN=X\tName=X\tPri=X...
 */
app.post("/api/users", (req, res) => {
    const { sn, pin, name, privilege = 0, password = "", card = "", group = 1, timezone = "0000000000000000" } = req.body;
    
    if (!sn || !pin || !name) {
        return res.status(400).json({ error: "Missing required fields: sn, pin, name" });
    }

    const cmdId = Date.now().toString();
    
    // Protocol 12.1.1.1: DATA UPDATE USERINFO
    // CRITICAL: Must use actual tab character (\t), not HT variable
    const cmd = `C:${cmdId}:DATA UPDATE USERINFO PIN=${pin}\tName=${name}\tPri=${privilege}\tPasswd=${password}\tCard=${card}\tGrp=${group}\tTZ=${timezone}\tVerify=-1`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`👤 CREATE USER queued: ${name} (PIN: ${pin}, CmdID: ${cmdId})`);
    console.log(`📤 Command format check: ${cmd.replace(/\t/g, '[TAB]')}`);
    
    res.json({ 
        success: true, 
        message: `User ${name} creation queued`,
        cmdId,
        data: { pin, name, privilege, card, group }
    });
});

/**
 * READ USER
 * Protocol: Section 12.1.3 - Query User Information
 * Format: C:${CmdID}:DATA QUERY USERINFO PIN=X
 */
app.get("/api/users/:pin", (req, res) => {
    const { sn } = req.query;
    const { pin } = req.params;
    
    if (!sn) {
        return res.status(400).json({ error: "Missing device serial number (sn)" });
    }

    const cmdId = Date.now().toString();
    const cmd = `C:${cmdId}:DATA QUERY USERINFO PIN=${pin}`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`🔍 QUERY USER: PIN ${pin} (CmdID: ${cmdId})`);
    res.json({ 
        success: true, 
        message: `Query for user ${pin} queued`,
        cmdId,
        note: "Check device logs or use GET /api/command-result/:cmdId"
    });
});

/**
 * READ ALL USERS
 * Protocol: Section 12.1.3 - Query all users
 * Format: C:${CmdID}:DATA QUERY USERINFO
 */
app.get("/api/users", (req, res) => {
    const { sn } = req.query;
    
    if (!sn) {
        return res.status(400).json({ error: "Missing device serial number (sn)" });
    }

    const cmdId = Date.now().toString();
    const cmd = `C:${cmdId}:DATA QUERY USERINFO`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`🔍 QUERY ALL USERS (CmdID: ${cmdId})`);
    res.json({ 
        success: true, 
        message: "Query all users queued",
        cmdId,
        note: "Device will upload user data via POST /iclock/cdata"
    });
});

/**
 * UPDATE USER
 * Protocol: Section 12.1.1.1 - User Information (same as CREATE)
 * Format: C:${CmdID}:DATA UPDATE USERINFO PIN=X\tName=X...
 */
app.put("/api/users/:pin", (req, res) => {
    const { sn, name, privilege, password, card, group, timezone } = req.body;
    const { pin } = req.params;
    
    if (!sn) {
        return res.status(400).json({ error: "Missing device serial number (sn)" });
    }

    const cmdId = Date.now().toString();
    
    // Build command with actual \t characters
    let cmd = `C:${cmdId}:DATA UPDATE USERINFO PIN=${pin}`;
    if (name !== undefined) cmd += `\tName=${name}`;
    if (privilege !== undefined) cmd += `\tPri=${privilege}`;
    if (password !== undefined) cmd += `\tPasswd=${password}`;
    if (card !== undefined) cmd += `\tCard=${card}`;
    if (group !== undefined) cmd += `\tGrp=${group}`;
    if (timezone !== undefined) cmd += `\tTZ=${timezone}`;
    cmd += `\tVerify=-1`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`✏️  UPDATE USER: PIN ${pin} (CmdID: ${cmdId})`);
    console.log(`📤 Command format check: ${cmd.replace(/\t/g, '[TAB]')}`);
    
    res.json({ 
        success: true, 
        message: `User ${pin} update queued`,
        cmdId,
        updatedFields: { name, privilege, password, card, group, timezone }
    });
});

/**
 * DELETE USER
 * Protocol: Section 12.1.2.1 - Delete User Information
 * Format: C:${CmdID}:DATA DELETE USERINFO PIN=X
 */
app.delete("/api/users/:pin", (req, res) => {
    const { sn } = req.query;
    const { pin } = req.params;
    
    if (!sn) {
        return res.status(400).json({ error: "Missing device serial number (sn)" });
    }

    const cmdId = Date.now().toString();
    const cmd = `C:${cmdId}:DATA DELETE USERINFO PIN=${pin}`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`🗑️  DELETE USER: PIN ${pin} (CmdID: ${cmdId})`);
    res.json({ 
        success: true, 
        message: `User ${pin} deletion queued`,
        cmdId,
        note: "This deletes user info, fingerprints, face templates, and photos"
    });
});

// ---------------------------------------------------------
// 7. UTILITY ENDPOINTS
// ---------------------------------------------------------

// Check command execution result
app.get("/api/command-result/:cmdId", (req, res) => {
    const { cmdId } = req.params;
    const result = commandResults[cmdId];
    
    if (!result) {
        return res.json({ 
            success: false, 
            message: "Command result not yet received or command ID not found",
            cmdId 
        });
    }
    
    res.json({
        success: result.success,
        cmdId,
        returnCode: result.returnCode,
        cmdType: result.cmdType,
        timestamp: result.timestamp,
        message: result.success ? "Command executed successfully" : `Command failed with code ${result.returnCode}`
    });
});

// Health check
app.get("/health", (req, res) => {
    res.json({
        devices,
        queuedCommands: Object.keys(commandQueue).reduce((acc, sn) => {
            acc[sn] = commandQueue[sn].length;
            return acc;
        }, {}),
        timestamp: new Date().toISOString()
    });
});

// Queue status
app.get("/api/queue/:sn", (req, res) => {
    const { sn } = req.params;
    res.json({
        device: sn,
        queueLength: commandQueue[sn] ? commandQueue[sn].length : 0,
        pendingCommands: commandQueue[sn] || []
    });
});

// Clear queue
app.delete("/api/queue/:sn", (req, res) => {
    const { sn } = req.params;
    const cleared = commandQueue[sn] ? commandQueue[sn].length : 0;
    commandQueue[sn] = [];
    res.json({ success: true, message: `Cleared ${cleared} commands from queue` });
});

// ---------------------------------------------------------
// START SERVER
// ---------------------------------------------------------
app.listen(PORT, "0.0.0.0", () => {
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║   🚀 ZKTeco PUSH Protocol API Server v2.4.2                   ║
║   Based on Official ZKTeco SDK Documentation (July 2024)      ║
╚════════════════════════════════════════════════════════════════╝

Server running at: http://localhost:${PORT}

📡 Protocol Endpoints:
  POST /iclock/registry          - Device registration
  GET  /iclock/cdata?options=all - Configuration exchange
  POST /iclock/cdata             - Data upload (attendance, etc)
  GET  /iclock/getrequest        - Command polling
  POST /iclock/devicecmd         - Command results

👤 User CRUD API:
  POST   /api/users              - Create user
  GET    /api/users/:pin         - Query user
  GET    /api/users              - Query all users
  PUT    /api/users/:pin         - Update user
  DELETE /api/users/:pin         - Delete user

🔧 Utility API:
  GET    /health                 - Server health
  GET    /api/queue/:sn          - Queue status
  DELETE /api/queue/:sn          - Clear queue
  GET    /api/command-result/:id - Check command result

Waiting for device connections...
`);
});