const express = require("express");
const app = express();
const PORT = 8080;

// Capture raw text - critical for ZK protocol
app.use(express.text({ type: "*/*" }));

// =========================================================
// STATE
// =========================================================
let devices = {};       // { [SN]: { lastSeen, status, timestamp } }
let commandQueue = {};  // { [SN]: string[] }
let cmdResults = {};    // { [cmdId]: { Return, CMD, raw } }
let cmdCounter = 1;     // Sequential CmdID counter (doc: must not be 0, must increment)

const getNextCmdId = () => cmdCounter++;

const updateDeviceHealth = (sn) => {
    if (!sn) return;
    const now = new Date();
    devices[sn] = {
        lastSeen: now.toLocaleString(),
        status: "Online",
        timestamp: now.getTime()
    };
};

// Mark devices offline if not seen in 90 seconds
setInterval(() => {
    const now = Date.now();
    Object.keys(devices).forEach(sn => {
        if (now - devices[sn].timestamp > 90000) {
            devices[sn].status = "Offline";
        }
    });
}, 15000);


// =========================================================
// 1. INITIALIZATION  (Doc: Step 1 — GET /iclock/cdata)
//    Device's very first request after boot. Reply 200 OK.
// =========================================================
app.get("/iclock/cdata", (req, res) => {
    const { SN, options } = req.query;
    updateDeviceHealth(SN);

    // Step 3 — Push/config download: device sends ?options=all
    if (options === "all") {
        console.log(`⚙️  CONFIG PUSH for SN: ${SN}`);
        const now = Math.floor(Date.now() / 1000);

        const config = [
            `GET OPTION FROM: ${SN}`,
            `Stamp=${now}`,
            `OpStamp=${now}`,
            `ErrorDelay=30`,
            `Delay=10`,
            `TransInterval=1`,
            `TransTimes=00:00;14:00`,
            `TransFlag=1111000000`,
            `Realtime=1`,
            `Encrypt=0`,
            `ServerVer=3.0.1`,
            `ServerName=ADMS`,
            `PushVer=3.0.1`,
            `TimeoutSec=10`,
            `SessionID=${now}`,
            `Compatibility=1`
        ].join("\r\n") + "\r\n";

        res.set("Content-Type", "text/plain");
        return res.send(config);
    }

    // Default initialization reply
    console.log(`🔌 Initialization request from SN: ${SN}`);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 2. REGISTRATION  (Doc: Step 2 — POST /iclock/registry)
//    Doc: server must reply with a 10-digit random number
//    as RegistryCode. Not "OK" — firmware checks this.
// =========================================================
app.post("/iclock/registry", (req, res) => {
    const { SN } = req.query;
    console.log(`📝 Registry Request from SN: ${SN}`);
    updateDeviceHealth(SN);

    // Generate compliant 10-digit registration code
    const registryCode = Math.floor(1000000000 + Math.random() * 9000000000);

    res.set("Content-Type", "text/plain");
    res.send(`RegistryCode=${registryCode}\n`);
});


// =========================================================
// 3. PUSH / CONFIG DOWNLOAD  (Doc: Step 3 — /iclock/push)
//    Separate endpoint from cdata. Device downloads server
//    config parameters here.
// =========================================================
app.get("/iclock/push", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    console.log(`📥 Push config request from SN: ${SN}`);

    const now = Math.floor(Date.now() / 1000);

    const config = [
        `ServerVersion=3.0.1`,
        `ServerName=ADMS`,
        `PushVersion=3.0.1`,
        `ErrorDelay=30`,
        `RequestDelay=2`,
        `TransTimes=00:00;14:00`,
        `TransInterval=1`,
        `TransTables=User Transaction`,
        `Realtime=1`,
        `SessionID=${now}`,
        `TimeoutSec=10`
    ].join("\r\n") + "\r\n";

    res.set("Content-Type", "text/plain");
    res.send(config);
});

app.post("/iclock/push", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    console.log(`📤 Push POST from SN: ${SN}`, req.body || "");
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 4. DATA UPLOAD  (Doc: Step 5 — POST /iclock/cdata)
//    Handles all table uploads from the device.
// =========================================================
app.post("/iclock/cdata", (req, res) => {
    const { SN, table } = req.query;
    updateDeviceHealth(SN);
    console.log(`📦 Data upload from SN: ${SN}, table: ${table}`);

    const rawData = req.body ? req.body.trim() : "";

    // --- Attendance / Real-time log ---
    if (table === "rtlog" || table === "ATTLOG") {
        const lines = rawData.split("\n");
        lines.forEach(line => {
            if (!line) return;
            const dataObj = {};
            line.split("\t").forEach(pair => {
                const [key, value] = pair.split("=");
                if (key && value !== undefined) dataObj[key.trim()] = value.trim();
            });
            console.log(`✅ [${table}] PIN=${dataObj.pin || dataObj.PIN || '??'} Time=${dataObj.time || dataObj.Time || '??'} Event=${dataObj.event || '??'}`);
        });
        return res.send("OK\n");
    }

    // --- Real-time access control event ---
    if (table === "rtevent") {
        const lines = rawData.split("\n");
        lines.forEach(line => {
            if (!line) return;
            console.log(`🚪 [rtevent] ${SN}: ${line}`);
        });
        return res.send("OK\n");
    }

    // --- Real-time device state (door sensors, relays) ---
    if (table === "rtstate") {
        console.log(`📡 [rtstate] SN: ${SN} | ${rawData}`);
        // relay=XX : each bit = relay state per door (0=on, 1=off)
        // sensor=XX: each 2 bits = door sensor state (00=none, 01=closed, 10=open)
        const stateObj = {};
        rawData.split(/[\r\n&]+/).forEach(pair => {
            const [k, v] = pair.split("=");
            if (k && v !== undefined) stateObj[k.trim()] = v.trim();
        });
        if (stateObj.relay !== undefined) {
            const relayBits = parseInt(stateObj.relay, 16);
            console.log(`   🔌 Relay bits: ${relayBits.toString(2).padStart(8, "0")}`);
        }
        if (stateObj.sensor !== undefined) {
            const sensorBits = parseInt(stateObj.sensor, 16);
            console.log(`   🚪 Sensor bits: ${sensorBits.toString(2).padStart(8, "0")}`);
        }
        return res.send("OK\n");
    }

    // --- Operation log ---
    if (table === "OPERLOG") {
        const lines = rawData.split("\n");
        lines.forEach(line => {
            if (!line) return;
            const parts = line.split(/\s+/);
            const opType = parts[1];
            const targetPin = parts[5];
            if (opType === "30") {
                console.log(`🎊 [OPERLOG] Device ${SN} created User PIN: ${targetPin}`);
            } else {
                console.log(`📋 [OPERLOG] SN: ${SN} opType=${opType} raw: ${line}`);
            }
        });
        return res.send(`OK: ${lines.length}\n`);
    }

    // --- User info upload ---
    if (table === "user") {
        console.log(`👤 [user upload] SN: ${SN}\n${rawData}`);
        return res.send("OK\n");
    }

    // --- Biometric photo ---
    if (table === "biophoto") {
        console.log(`📸 [biophoto] SN: ${SN} — ${rawData.length} bytes`);
        return res.send("OK\n");
    }

    // --- Fingerprint template ---
    if (table === "templatev10") {
        console.log(`🖐️  [templatev10] SN: ${SN} — ${rawData.length} bytes`);
        return res.send("OK\n");
    }

    // --- Biodata (all-in-one visible light template) ---
    if (table === "biodata") {
        console.log(`🧬 [biodata] SN: ${SN} — ${rawData.length} bytes`);
        return res.send("OK\n");
    }

    // --- Snapshot / user photo ---
    if (table === "snapshot" || table === "userpic") {
        console.log(`🖼️  [${table}] SN: ${SN} — ${rawData.length} bytes`);
        return res.send("OK\n");
    }

    // --- Error log ---
    if (table === "errorlog") {
        console.log(`⚠️  [errorlog] SN: ${SN}: ${rawData}`);
        return res.send("OK\n");
    }

    // Fallback for unknown tables
    console.log(`❓ [unknown table: ${table}] SN: ${SN}: ${rawData}`);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 5. HEARTBEAT / COMMAND POLLING  (Doc: Step 4)
//    Device polls here continuously. Server drains queue
//    one command at a time.
// =========================================================
app.get("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);

    res.set("Content-Type", "text/plain");

    if (commandQueue[SN] && commandQueue[SN].length > 0) {
        const cmd = commandQueue[SN].shift();
        console.log(`🚀 Sending Command to ${SN}: ${cmd.replace(/\r\n/g, " | ")}`);
        return res.send(cmd + "\n");
    }

    res.send("OK\n");
});


// =========================================================
// 6. COMMAND RESULT RETURN  (Doc: Step 7 — /iclock/devicecmd)
//    After executing a command the device posts the result
//    here. Format: ID=<cmdId>&Return=<0=success>&CMD=<type>
// =========================================================
app.post("/iclock/devicecmd", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);

    const raw = req.body ? req.body.trim() : "";
    console.log(`🎯 [devicecmd] SN: ${SN} result: ${raw}`);

    // Parse: ID=1&Return=0&CMD=DATA UPDATE
    const resultObj = {};
    raw.split("&").forEach(pair => {
        const [k, v] = pair.split("=");
        if (k) resultObj[k.trim()] = v ? v.trim() : "";
    });

    const cmdId = resultObj["ID"];
    const returnCode = resultObj["Return"];
    const cmdType = resultObj["CMD"];

    if (cmdId) {
        cmdResults[cmdId] = { Return: returnCode, CMD: cmdType, raw, receivedAt: new Date().toISOString() };
        if (returnCode === "0") {
            console.log(`   ✅ CmdID ${cmdId} [${cmdType}] succeeded`);
        } else {
            console.log(`   ❌ CmdID ${cmdId} [${cmdType}] FAILED (Return=${returnCode})`);
        }
    }

    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// Also accept result on getrequest POST (some older firmware uses this)
app.post("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    const result = req.body ? req.body.trim() : "";
    console.log(`🎯 [getrequest POST] SN: ${SN} result: ${result}`);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 7. BACKUP HEARTBEAT  (Doc: Step 6 — /iclock/ping)
//    Used to keep alive during large data uploads.
//    Always reply OK.
// =========================================================
app.get("/iclock/ping", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    // No logging — too frequent
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

app.post("/iclock/ping", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 8. QUERY DATA EXTENDED  (Doc: Extended interface)
//    Device uploads query results to /iclock/querydata
// =========================================================
app.post("/iclock/querydata", (req, res) => {
    const { SN, table } = req.query;
    updateDeviceHealth(SN);
    const rawData = req.body ? req.body.trim() : "";
    console.log(`🔍 [querydata] SN: ${SN} table: ${table}`);
    console.log(`   Data: ${rawData}`);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 9. MANAGEMENT API
// =========================================================

// --- Add member (user + authorize) ---
app.get("/add-member", (req, res) => {
    const { sn, id, name, timezone, door } = req.query;
    if (!sn || !id || !name) return res.status(400).send("Missing: sn, id, name");

    const tzId = timezone || "1";
    const doorId = door || "1";

    const cmdId1 = getNextCmdId();
    const cmdId2 = getNextCmdId();

    // Create user
    const cmdUser = [
        `C:${cmdId1}:DATA UPDATE user`,
        `PIN=${id}`,
        `Name=${name}`,
        `Pri=0`,
        `Passwd=`,
        `Card=`,
        `Grp=1`,
        `TZ=${tzId}`,
        `Verify=-1`,
        `ViceCard=`,
        `StartDatetime=0`,
        `EndDatetime=0`
    ].join("\t");

    // Assign access rights
    const cmdAuthorize = [
        `C:${cmdId2}:DATA UPDATE userauthorize`,
        `PIN=${id}`,
        `AuthorizeTimezoneId=${tzId}`,
        `AuthorizeDoorId=${doorId}`
    ].join("\t");

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmdUser, cmdAuthorize);

    console.log(`✅ [ADD MEMBER] Queued for ${sn}: CmdID=${cmdId1},${cmdId2} PIN=${id} Name=${name}`);
    res.json({ status: "queued", pin: id, name, cmdIds: [cmdId1, cmdId2] });
});


// --- Delete member (delete authorize first, then user — per doc warning) ---
app.get("/delete-member", (req, res) => {
    const { sn, id } = req.query;
    if (!sn || !id) return res.status(400).send("Missing: sn, id");

    const cmdId1 = getNextCmdId();
    const cmdId2 = getNextCmdId();

    // Must delete userauthorize BEFORE user (doc section 2.2)
    const cmdDelAuth = `C:${cmdId1}:DATA DELETE userauthorize\tPIN=${id}`;
    const cmdDelUser = `C:${cmdId2}:DATA DELETE user\tPIN=${id}`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmdDelAuth, cmdDelUser);

    console.log(`🗑️  [DELETE MEMBER] Queued for ${sn}: PIN=${id} CmdIDs=${cmdId1},${cmdId2}`);
    res.json({ status: "queued", pin: id, cmdIds: [cmdId1, cmdId2] });
});


// --- Update member timezone (delete auth + re-add — per doc section 2.2) ---
app.get("/update-timezone", (req, res) => {
    const { sn, id, timezone, door } = req.query;
    if (!sn || !id || !timezone) return res.status(400).send("Missing: sn, id, timezone");

    const doorId = door || "1";
    const cmdId1 = getNextCmdId();
    const cmdId2 = getNextCmdId();

    // Doc: MUST delete old timezone before assigning new one
    const cmdDelAuth = `C:${cmdId1}:DATA DELETE userauthorize\tPIN=${id}`;
    const cmdNewAuth = [
        `C:${cmdId2}:DATA UPDATE userauthorize`,
        `PIN=${id}`,
        `AuthorizeTimezoneId=${timezone}`,
        `AuthorizeDoorId=${doorId}`
    ].join("\t");

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmdDelAuth, cmdNewAuth);

    console.log(`🕐 [UPDATE TIMEZONE] Queued for ${sn}: PIN=${id} -> TZ=${timezone}`);
    res.json({ status: "queued", pin: id, timezone, cmdIds: [cmdId1, cmdId2] });
});


// --- Query users ---
app.get("/query-users", (req, res) => {
    const { sn, pin } = req.query;
    if (!sn) return res.status(400).send("Missing: sn");

    const cmdId = getNextCmdId();
    const filter = pin ? `Pin=${pin}` : `*`;
    const cmd = `C:${cmdId}:DATA QUERY tablename=user,fielddesc=*,filter=${filter}`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);

    res.json({ status: "queued", cmdId });
});


// --- Open door ---
app.get("/open-door", (req, res) => {
    const { sn, door, seconds } = req.query;
    if (!sn) return res.status(400).send("Missing: sn");

    const cmdId = getNextCmdId();
    const doorNum = (door || "1").padStart(2, "0");
    const secs = (seconds || "5").padStart(2, "0");

    // Format: AABBCCDDEE — AA=01(door open), BB=door num, CC=00, DD=seconds
    const controlCode = `01${doorNum}00${secs}`;
    const cmd = `C:${cmdId}:CONTROL DEVICE ${controlCode}`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);

    console.log(`🚪 [OPEN DOOR] Queued for ${sn}: Door ${door || 1} for ${secs}s CmdID=${cmdId}`);
    res.json({ status: "queued", cmdId, controlCode });
});


// --- Reboot device ---
app.get("/reboot-device", (req, res) => {
    const { sn } = req.query;
    if (!sn) return res.status(400).send("Missing: sn");

    const cmdId = getNextCmdId();
    const cmd = `C:${cmdId}:CONTROL DEVICE 03000000`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);

    console.log(`🔄 [REBOOT] Queued for ${sn} CmdID=${cmdId}`);
    res.json({ status: "queued", cmdId });
});


// --- Issue timezone rule ---
app.get("/set-timezone", (req, res) => {
    const { sn, tzid, monstart, monend } = req.query;
    if (!sn || !tzid) return res.status(400).send("Missing: sn, tzid");

    const cmdId = getNextCmdId();

    // Doc: TimezoneId=1 means 24hr access. Value is (start<<16 + end)
    // Default: full-day access (00:00-23:59)
    const startMins = monstart ? parseInt(monstart.replace(":", "")) : 0;
    const endMins = monend ? parseInt(monend.replace(":", "")) : 2359;
    const monTime = startMins * 65536 + endMins;

    const cmd = [
        `C:${cmdId}:DATA UPDATE timezone`,
        `TimezoneId=${tzid}`,
        `MonTime1=${monTime}`,
        `TueTime1=${monTime}`,
        `WedTime1=${monTime}`,
        `ThuTime1=${monTime}`,
        `FriTime1=${monTime}`,
        `SatTime1=0`,
        `SunTime1=0`
    ].join("\t");

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);

    res.json({ status: "queued", cmdId, tzid, monTime });
});


// --- View command result ---
app.get("/cmd-result", (req, res) => {
    const { id } = req.query;
    if (!id) return res.json(cmdResults);
    res.json(cmdResults[id] || { error: "Not found" });
});


// --- Device health dashboard ---
app.get("/devices", (req, res) => {
    res.json(devices);
});


// --- Health check ---
app.get("/health", (req, res) => {
    res.json({ status: "ok", uptime: process.uptime(), devices: Object.keys(devices).length });
});

// Legacy spelling kept for compatibility
app.get("/helths", (req, res) => res.send("ok"));


// =========================================================
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 ZK ADMS Push Protocol Server (fully compliant) running on port ${PORT}`);
    console.log(`   Endpoints: /iclock/registry, /iclock/cdata, /iclock/push,`);
    console.log(`              /iclock/getrequest, /iclock/ping, /iclock/devicecmd, /iclock/querydata`);
});