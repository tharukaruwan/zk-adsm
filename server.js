const express = require("express");
const app = express();
const PORT = 8081;

// Capture raw text - critical for ZK protocol
app.use(express.text({ type: "*/*" }));

let devices = {};       
let commandQueue = {};  

const updateDeviceHealth = (sn) => {
    if (!sn) return;
    const now = new Date();
    devices[sn] = { lastSeen: now.toLocaleString(), status: "Online", timestamp: now.getTime() };
};

// ---------------------------------------------------------
// 1. REGISTRY HANDLER (Document Chapter 3.1)
// ---------------------------------------------------------
app.post("/iclock/registry", (req, res) => {
    const { SN } = req.query;
    console.log(`📝 Registry Request from SN: ${SN}`);
    updateDeviceHealth(SN);
    res.set("Content-Type", "text/plain");
    // RegistryCode=OK tells device it's authorized to link to this server
    res.send("RegistryCode=OK\n"); 
});

// ---------------------------------------------------------
// 2. DATA HANDLER (Document Chapter 3.2 & 3.3)
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
            console.log(`✅ [${table}] User ${dataObj.pin || '??'} at ${dataObj.time || '??'}`);
        });
    }
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 3. HANDSHAKE / CONFIG (Document Chapter 3.4)
// ---------------------------------------------------------
app.get("/iclock/cdata", (req, res) => {
    const { SN, options } = req.query;
    updateDeviceHealth(SN);

    if (options === "all") {
        console.log(`⚙️  AUTHORIZING HANDSHAKE for SN: ${SN}`);
        const now = Math.floor(Date.now() / 1000);
        
        // Critical block to stop the blinking yellow icon (Linux Firmware Compatibility)
        const config = [
            `GET OPTION FROM: ${SN}`,
            `Stamp=${now}`,
            `OpStamp=${now}`,
            `ErrorDelay=60`,
            `Delay=30`,
            `TransInterval=1`,
            `TransFlag=1111000000`,
            `Realtime=1`,
            `Encrypt=0`,
            `ServerVer=3.4.1`,
            `PushVer=3.2.1`,
            `ADMSVer=1.0.0`,
            `SessionID=${now}`,   
            `Compatibility=1`     
        ].join("\r\n") + "\r\n";

        res.set("Content-Type", "text/plain");
        return res.send(config);
    }
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 4. COMMAND POLLING (Document Chapter 4)
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

// Result Confirmation (Document Chapter 4.2)
app.post("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    const result = req.body ? req.body.trim() : "";
    console.log(`🎯 Device ${SN} Result: ${result}`);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// ---------------------------------------------------------
// 5. API ENDPOINTS (Corrected per Chapter 4.1.2)
// ---------------------------------------------------------
app.get("/add-member", (req, res) => {
  const { sn, id, name } = req.query;
  const cmdId = Math.floor(Math.random() * 10000);

  // 1. Change USERID to PIN (Critical)
  // 2. Ensure the command starts with C:ID:DATA UPDATE USER
  // 3. Use \t (Tabs) as shown in the documentation example
  const cmd = [
    `C:${cmdId}:DATA UPDATE USER PIN=${id}`, // Command header
    `Name=${name}`,
    `Pri=0`,
    `Passwd=`,
    `Card=`,
    `Grp=1`,
    `TZ=0000000000000000`,
    `Verify=-1`
  ].join("\t");

  if (!commandQueue[sn]) commandQueue[sn] = [];
  commandQueue[sn].push(cmd);

  console.log("CORRECTED CMD SENT:", cmd);
  res.send(`User ${name} queued with PIN ${id}`);
});


app.get("/delete-member", (req, res) => {
    const { sn, id } = req.query;
    const cmdId = Math.floor(Math.random() * 10000);
    
    // Protocol requires C:ID prefix for deletions
    const cmd = `C:${cmdId}:DATA DELETE USER PIN=${id}`;
    
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    res.send(`Delete ID ${id} queued with ID ${cmdId}`);
});

app.get("/query-users", (req, res) => {
    const { sn } = req.query;
    const cmdId = Math.floor(Math.random() * 10000);
    
    // Official syntax for querying the user table
    const cmd = `C:${cmdId}:DATA QUERY USER`;
    
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(cmd);
    res.send(`Query command queued with ID ${cmdId}`);
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Fitrobit Protocol V4.8 Server online at http://localhost:${PORT}`);
});