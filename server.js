const express = require("express");
const app = express();
const PORT = 8081;

app.use(express.text({ type: "*/*" }));

// ---------------------------------------------------------
// DATABASE SIMULATION (Replace with MySQL/MongoDB later)
// ---------------------------------------------------------
let devices = {};       // Stores { SN: { lastSeen: Date, status: 'online' } }
let commandQueue = {};  // Stores { SN: [ 'command1', 'command2' ] }

// ---------------------------------------------------------
// 1. DEVICE HEALTH & LAST SEEN TRACKER
// ---------------------------------------------------------
const updateDeviceHealth = (sn) => {
    devices[sn] = {
        lastSeen: new Date().toLocaleString(),
        status: "Online"
    };
};

// ---------------------------------------------------------
// 2. REGISTRY HANDLER (Initial Connection)
// ---------------------------------------------------------
app.post("/iclock/registry", (req, res) => {
    const { SN } = req.query;
    console.log(`📝 Registry Request from SN: ${SN}`);
    updateDeviceHealth(SN);
    
    res.set("Content-Type", "text/plain");
    res.send("RegistryCode=OK\n"); 
});

// ---------------------------------------------------------
// 3. ATTENDANCE TRACKER (Online & Offline Logs)
// ---------------------------------------------------------
app.post("/iclock/cdata", (req, res) => {
    const { SN, table } = req.query;
    updateDeviceHealth(SN);

    // table=rtlog is live punch | table=ATTLOG is offline logs being synced
    if (table === "rtlog" || table === "ATTLOG") {
        const rawData = req.body.trim();
        const lines = rawData.split("\n");

        lines.forEach(line => {
            const dataObj = {};
            line.split("\t").forEach(pair => {
                const [key, value] = pair.split("=");
                if (key && value) dataObj[key] = value;
            });

            // Tracking details: PIN, Time, and Device SN
            const punch = {
                userId: dataObj.pin || "Unknown",
                time: dataObj.time || "No Time",
                sn: SN,
                mode: table === "rtlog" ? "Real-time" : "Sync (Offline Log)"
            };

            console.log(`✅ [${punch.mode}] User ${punch.userId} entered at ${punch.time}`);
        });
    }

    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 4. COMMAND POLLING (Manage Members / Configs)
// ---------------------------------------------------------
app.get("/iclock/getrequest", (req, res) => {
    console.log('req.query = ', req.query);
    console.log('req.body = ', req.body);
    const { SN } = req.query;
    updateDeviceHealth(SN);
    res.set("Content-Type", "text/plain");

    // Check if there are commands for this specific device
    if (commandQueue[SN] && commandQueue[SN].length > 0) {
        const cmd = commandQueue[SN].shift();
        console.log(`🚀 Sending Command to ${SN}: ${cmd}`);
        return res.send(cmd + "\n");
    }

    res.send("OK\n");
});

// ---------------------------------------------------------
// 5. MEMBER MANAGEMENT & CONFIGURATION API
// ---------------------------------------------------------

/**
 * MEMBER REGISTRATION ENDPOINT
 * This handles your requirement #3: Adding/Updating members.
 * * URL: /add-member?sn=NYU7253200164&id=101&name=Saman
 */
app.get("/add-member", (req, res) => {
    const { sn, id, name } = req.query;

    if (!sn || !id || !name) {
        return res.status(400).send("Missing parameters: sn, id, or name");
    }

    const cmdId = Math.floor(Math.random() * 10000);
    
    // Command String:
    // PIN  = The unique ID
    // Name = The Display Name
    // Pri  = 0 (Normal User)
    // Grp  = 1 (Default Group)
    const cmd = `C:${cmdId}:DATA USER PIN=${id}\tName=${name}\tPri=0\tGrp=1`;

    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);

    console.log(`👤 MEMBER QUEUED: ${name} (ID: ${id}) for Device ${sn}`);
    res.send(`Member ${name} queued. Device will sync on next 5s heartbeat.`);
});

/**
 * DELETE MEMBER
 * Example: /delete-member?sn=YOUR_SN&id=101
 */
app.get("/delete-member", (req, res) => {
    const { sn, id } = req.query;
    const cmdId = Math.floor(Math.random() * 10000);
    
    const cmd = `C:${cmdId}:DATA DELETE USER PIN=${id}`;
    
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    res.send(`User ID ${id} queued for deletion from ${sn}`);
});

/**
 * VIEW DEVICE HEALTH
 */
app.get("/health", (req, res) => {
    res.json(devices);
});

// ---------------------------------------------------------
// CONFIGURATION HANDLER (Updated for 5-second health check)
// ---------------------------------------------------------
app.get("/iclock/cdata", (req, res) => {
    const { SN, options } = req.query;
    console.log(`⚙️ Configuration Request from SN: ${SN} with options: ${options}`);
    updateDeviceHealth(SN);

    if (options === "all") {
        console.log(`⚙️ Setting heartbeat to 5 seconds for SN: ${SN}`);
        const now = Math.floor(Date.now() / 1000);
        
        const config = [
            `GET OPTION FROM: ${SN}`,
            `Stamp=${now}`,
            `OpStamp=${now}`,
            `Realtime=1`,
            `Delay=5`,          // <--- Changed from 30 to 5 (Heartbeat frequency)
            `TransInterval=1`,  // <--- Send logs immediately
            `ErrorDelay=5`,     // <--- Retry quickly if a connection fails
            `TransFlag=1111000000`,
            `Encrypt=0`
        ].join("\r\n") + "\r\n";

        res.set("Content-Type", "text/plain");
        return res.send(config);
    }
    res.send("OK\n");
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Fitrobit Server online at http://localhost:${PORT}`);
});