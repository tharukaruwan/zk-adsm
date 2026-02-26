const express = require("express");
const app = express();
const PORT = 8081;

app.use(express.text({ type: "*/*" }));

let devices = {};       
let commandQueue = {};  
let commandResults = {}; // Store command execution results

const updateDeviceHealth = (sn) => {
    if (!sn) return;
    const now = new Date();
    devices[sn] = { lastSeen: now.toLocaleString(), status: "Online", timestamp: now.getTime() };
};

// ---------------------------------------------------------
// REGISTRY HANDLER
// ---------------------------------------------------------
app.post("/iclock/registry", (req, res) => {
    const { SN } = req.query;
    console.log(`📝 Registry Request from SN: ${SN}`);
    updateDeviceHealth(SN);
    res.set("Content-Type", "text/plain");
    res.send("RegistryCode=OK\n"); 
});

// ---------------------------------------------------------
// DATA HANDLER - Now handles OPERLOG too
// ---------------------------------------------------------
app.post("/iclock/cdata", (req, res) => {
    const { SN, table } = req.query;
    updateDeviceHealth(SN);

    // Handle attendance logs
    if (table === "rtlog" || table === "ATTLOG") {
        const rawData = req.body ? req.body.trim() : "";
        const lines = rawData.split("\n");

        lines.forEach(line => {
            if (!line) return;
            const dataObj = {};
            line.split("\t").forEach(pair => {
                const [key, value] = pair.split("=");
                if (key && value) dataObj[key] = value;
            });
            console.log(`✅ [${table}] User ${dataObj.pin || '??'} at ${dataObj.time || '??'}`);
        });
    }
    
    // Handle operation logs (device-side operations)
    if (table === "OPERLOG") {
        const rawData = req.body ? req.body.trim() : "";
        const lines = rawData.split("\n");
        
        lines.forEach(line => {
            if (!line || !line.startsWith("OPLOG")) return;
            
            const parts = line.split("\t");
            const opType = parts[1];
            const opWho = parts[2];
            const opTime = parts[3];
            
            console.log(`📊 OPERLOG [Type ${opType}]: Operator=${opWho}, Time=${opTime}`);
            
            // Log specific operations
            const opNames = {
                "6": "Enroll fingerprint",
                "9": "Delete user",
                "30": "Enroll new user",
                "36": "Modify user info",
                "70": "Modify user name",
                "101": "Enroll face"
            };
            
            if (opNames[opType]) {
                console.log(`   ↳ ${opNames[opType]}`);
            }
        });
    }
    
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// HANDSHAKE / CONFIG
// ---------------------------------------------------------
app.get("/iclock/cdata", (req, res) => {
    const { SN, options } = req.query;
    updateDeviceHealth(SN);

    if (options === "all") {
        console.log(`⚙️  AUTHORIZING HANDSHAKE for SN: ${SN}`);
        const now = Math.floor(Date.now() / 1000);
        
        const config = [
            `GET OPTION FROM: ${SN}`,
            `Stamp=${now}`,
            `OpStamp=${now}`,
            `ErrorDelay=60`,
            `Delay=30`,
            `TransInterval=1`,
            `TransFlag=TransData AttLog OpLog AttPhoto EnrollUser ChgUser`, // Enable OPERLOG
            `Realtime=1`,
            `Encrypt=0`,
            `ServerVer=3.4.1`,
            `PushProtVer=2.4.2`,
            `SessionID=${now}`
        ].join("\r\n") + "\r\n";

        res.set("Content-Type", "text/plain");
        return res.send(config);
    }
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// COMMAND POLLING
// ---------------------------------------------------------
app.get("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    
    res.set("Content-Type", "text/plain");

    if (commandQueue[SN] && commandQueue[SN].length > 0) {
        const cmd = commandQueue[SN].shift();
        console.log(`🚀 Sending Command to ${SN}: ${cmd}`);
        return res.send(cmd + "\n");
    }
    res.send("OK\n");
});

// Result Confirmation - Store results for debugging
app.post("/iclock/devicecmd", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    const result = req.body ? req.body.trim() : "";
    
    // Parse result: ID=123&Return=0&CMD=DATA
    const resultData = {};
    result.split("&").forEach(pair => {
        const [key, value] = pair.split("=");
        if (key && value) resultData[key] = value;
    });
    
    console.log(`🎯 Device ${SN} Result:`, resultData);
    
    // Return=0 means success, negative means error (see Appendix 1)
    if (resultData.Return === "0") {
        console.log(`   ✅ Command ${resultData.ID} executed successfully!`);
    } else {
        console.log(`   ❌ Command ${resultData.ID} failed with code: ${resultData.Return}`);
    }
    
    // Store result for API query
    if (!commandResults[SN]) commandResults[SN] = [];
    commandResults[SN].push({ ...resultData, timestamp: new Date().toISOString() });
    
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// API ENDPOINTS - CORRECTED
// ---------------------------------------------------------
app.get("/add-member", (req, res) => {
    const { sn, id, name, card, password } = req.query;
    
    if (!sn || !id || !name) {
        return res.status(400).send("Missing required params: sn, id, name");
    }
    
    const cmdId = Math.floor(Math.random() * 10000);
    
    // CRITICAL FIX: Use USERINFO (not USER)
    // Format from Section 12.1.1.1
    const cmd = [
        `C:${cmdId}:DATA UPDATE USER`,
        `PIN=${id}`,
        `Name=${name}`,
        `Pri=0`,
        `Passwd=${password || ''}`,
        `Card=${card || ''}`,
        `Grp=1`,
        `TZ=0000000000000000`,
        `Verify=-1`
    ].join('\t'); // Join with TAB characters
    
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`✅ USER CREATE QUEUED (CmdID: ${cmdId}): PIN=${id}, Name=${name}`);
    res.json({ 
        success: true, 
        message: `User ${name} queued with PIN ${id}`,
        cmdId: cmdId,
        command: cmd
    });
});

app.get("/delete-member", (req, res) => {
    const { sn, id } = req.query;
    
    if (!sn || !id) {
        return res.status(400).send("Missing required params: sn, id");
    }
    
    const cmdId = Math.floor(Math.random() * 10000);
    
    // Section 12.1.2.1
    const cmd = `C:${cmdId}:DATA DELETE USERINFO PIN=${id}`;
    
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`🗑️  USER DELETE QUEUED (CmdID: ${cmdId}): PIN=${id}`);
    res.json({ 
        success: true, 
        message: `Delete user ${id} queued`,
        cmdId: cmdId 
    });
});

app.get("/query-users", (req, res) => {
    const { sn, pin } = req.query;
    
    if (!sn) {
        return res.status(400).send("Missing required param: sn");
    }
    
    const cmdId = Math.floor(Math.random() * 10000);
    
    // Section 12.1.3 - Query user info
    const cmd = pin 
        ? `C:${cmdId}:DATA QUERY USERINFO PIN=${pin}`
        : `C:${cmdId}:DATA QUERY USERINFO`;
    
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`🔍 USER QUERY QUEUED (CmdID: ${cmdId})`);
    res.json({ 
        success: true, 
        message: "Query queued",
        cmdId: cmdId 
    });
});

// Get command results
app.get("/command-results/:sn", (req, res) => {
    const { sn } = req.params;
    res.json(commandResults[sn] || []);
});

// Get device status
app.get("/devices", (req, res) => {
    res.json(devices);
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 ZKTeco PUSH Protocol Server v4.8 online at http://localhost:${PORT}`);
    console.log(`📚 API Endpoints:`);
    console.log(`   POST /add-member?sn=XXX&id=123&name=John`);
    console.log(`   POST /delete-member?sn=XXX&id=123`);
    console.log(`   POST /query-users?sn=XXX&pin=123`);
    console.log(`   GET  /devices`);
    console.log(`   GET  /command-results/:sn`);
});