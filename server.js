const express = require("express");
const app = express();
const PORT = 8081;

// Capture raw text - critical for ZK protocol
app.use(express.text({ type: "*/*" }));

// ---------------------------------------------------------
// DATABASE SIMULATION
// ---------------------------------------------------------
let devices = {};       
let commandQueue = {};  

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
// 1. REGISTRY HANDLER
// ---------------------------------------------------------
app.post("/iclock/registry", (req, res) => {
    const { SN } = req.query;
    console.log(`📝 Registry Request from SN: ${SN}`);
    updateDeviceHealth(SN);
    res.set("Content-Type", "text/plain");
    res.send("RegistryCode=OK\n"); 
});

// ---------------------------------------------------------
// 2. ATTENDANCE TRACKER (Online & Offline)
// ---------------------------------------------------------
app.post("/iclock/cdata", (req, res) => {
    const { SN, table } = req.query;
    updateDeviceHealth(SN);

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

            console.log(`✅ [${table}] User ${dataObj.pin || '??'} entered at ${dataObj.time || '??'}`);
        });
    }
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 3. COMMAND POLLING (GET) - Device asks for commands
// ---------------------------------------------------------
app.get("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    
    // Log heartbeat
    console.log(`💓 Heartbeat from ${SN} at ${new Date().toLocaleTimeString()}`);
    
    res.set("Content-Type", "text/plain");

    if (commandQueue[SN] && commandQueue[SN].length > 0) {
        const cmd = commandQueue[SN].shift();
        console.log(`🚀 Sending Command to ${SN}: ${cmd.replace(/\t/g, '[TAB]')}`);
        return res.send(cmd + "\n");
    }

    res.send("OK\n");
});

// ---------------------------------------------------------
// 4. COMMAND RESULT HANDLER (POST) - Device confirms execution
// ---------------------------------------------------------
app.post("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    
    const result = req.body ? req.body.trim() : "";
    console.log(`🎯 Device ${SN} execution result: ${result}`);
    
    // Parse the result to check if successful
    if (result.includes("Return=0")) {
        console.log("✅ Command executed successfully!");
    } else if (result.includes("Return=")) {
        console.log("⚠️  Command execution failed or returned error");
    }
    
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 5. MEMBER MANAGEMENT API (FIXED VERSION)
// ---------------------------------------------------------

app.get("/add-member", (req, res) => {
    const { sn, id, name, card = "" } = req.query;
    if (!sn || !id || !name) return res.status(400).send("Missing sn, id, or name");

    const cmdId = Math.floor(Math.random() * 10000);
    
    // CRITICAL FIX: Some devices need the command WITHOUT the "C:" prefix
    // Try this format first - it's more compatible with ZKTeco devices
    const fields = [
        `DATA USER PIN=${id}`,
        `Name=${name}`,
        `Pri=0`,
        `Passwd=`,
        `Card=${card}`,
        `Grp=1`,
        `TZ=0000000000000000`,
        `Verify=0`
    ];

    const cmd = fields.join("\t");

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);

    console.log(`👤 MEMBER QUEUED: ${name} (ID: ${id}) for device ${sn}`);
    res.send(`User ${name} (ID: ${id}) queued for ${sn}. Device will receive on next poll.`);
});

// Alternative format with C: prefix (try this if above doesn't work)
app.get("/add-member-alt", (req, res) => {
    const { sn, id, name, card = "" } = req.query;
    if (!sn || !id || !name) return res.status(400).send("Missing sn, id, or name");

    const cmdId = Math.floor(Math.random() * 10000);
    
    const cmd = `C:${cmdId}:DATA USER PIN=${id}\tName=${name}\tPri=0\tPasswd=\tCard=${card}\tGrp=1\tTZ=0000000000000000\tVerify=0`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);

    console.log(`👤 MEMBER QUEUED (ALT): ${name} (ID: ${id})`);
    res.send(`User ${name} queued with C: prefix format`);
});

app.get("/delete-member", (req, res) => {
    const { sn, id } = req.query;
    if (!sn || !id) return res.status(400).send("Missing sn or id");
    
    const cmd = `DATA DELETE USER PIN=${id}`;
    
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`🗑️  DELETE QUEUED: ID ${id} from ${sn}`);
    res.send(`Delete ID ${id} queued for ${sn}`);
});

// Query existing users (device will send them back)
app.get("/query-users", (req, res) => {
    const { sn } = req.query;
    if (!sn) return res.status(400).send("Missing sn");
    
    const cmd = "DATA QUERY USER";
    
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    
    console.log(`🔍 QUERY USERS queued for ${sn}`);
    res.send(`Query users command sent to ${sn}. Check server logs for response.`);
});

// ---------------------------------------------------------
// 6. CONFIGURATION HANDLER (HANDSHAKE)
// ---------------------------------------------------------
app.get("/iclock/cdata", (req, res) => {
    const { SN, options } = req.query;
    updateDeviceHealth(SN);

    if (options === "all") {
        console.log(`⚙️  Configuration request from ${SN}`);
        const now = Math.floor(Date.now() / 1000);
        
        const config = [
            `GET OPTION FROM: ${SN}`,
            `Stamp=${now}`,
            `OpStamp=${now}`,
            `ErrorDelay=30`,
            `Delay=5`,
            `TransInterval=1`,
            `TransFlag=1111000000`,
            `Realtime=1`,
            `Encrypt=0`,
            `ServerVer=3.4.1`,
            `PushVer=3.2.1`,
            `ADMSVer=1.0.0`
        ].join("\r\n") + "\r\n";

        res.set("Content-Type", "text/plain");
        return res.send(config);
    }
    
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// HEALTH & DEBUG ENDPOINTS
// ---------------------------------------------------------
app.get("/health", (req, res) => {
    res.json({
        devices,
        commandQueue,
        timestamp: new Date().toISOString()
    });
});

app.get("/queue-status", (req, res) => {
    const { sn } = req.query;
    if (sn) {
        res.json({
            device: sn,
            queueLength: commandQueue[sn] ? commandQueue[sn].length : 0,
            pendingCommands: commandQueue[sn] || []
        });
    } else {
        res.json(commandQueue);
    }
});

// ---------------------------------------------------------
// START SERVER
// ---------------------------------------------------------
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Fitrobit Server online at http://localhost:${PORT}`);
    console.log(`📡 Waiting for device connections...`);
    console.log(`\nAPI Endpoints:`);
    console.log(`  - Add user: http://localhost:${PORT}/add-member?sn=DEVICE_SN&id=USER_ID&name=USER_NAME`);
    console.log(`  - Delete user: http://localhost:${PORT}/delete-member?sn=DEVICE_SN&id=USER_ID`);
    console.log(`  - Query users: http://localhost:${PORT}/query-users?sn=DEVICE_SN`);
    console.log(`  - Health check: http://localhost:${PORT}/health`);
    console.log(`  - Queue status: http://localhost:${PORT}/queue-status?sn=DEVICE_SN\n`);
});