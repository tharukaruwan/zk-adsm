const express = require("express");
const app = express();
const PORT = 8080;

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
    console.log('req.query = ', req.query);
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

    if (table === "OPERLOG") {
        const lines = req.body.trim().split("\n");
        lines.forEach(line => {
            const parts = line.split(/\s+/); // Split by space/tabs
            const opType = parts[1];
            const targetPin = parts[5]; // Value1 in Appendix 4 is usually the User ID
            
            if (opType === "30") {
                console.log(`🎊 CONFIRMED: Device ${SN} successfully created User ID: ${targetPin}`);
            }
        });
        // Protocol requirement: Respond with record count
        return res.send(`OK: ${lines.length}\n`);
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
  if (!sn || !id || !name) {
    return res.status(400).send("Missing required parameters: sn, id, name");
  }

  const cmdId = Math.floor(Math.random() * 10000); // unique CmdID

  const cmdLines = [
    `C:${cmdId}:DATA UPDATE user`,
    `USER PIN=${id}`,
    `Name=${name}`,
    `Pri=0`,
    `Passwd=`,
    `Card=`,
    `Grp=1`,
    `TZ=1`,                    // default full access timezone
    `Verify=-1`,
    `ViceCard=`,
    `StartDatetime=0`,
    `EndDatetime=0`,
    `AuthorizeTimezoneId=1`,   // AC Push required
    `AuthorizeDoorId=1`        // AC Push required
  ];

  const cmd = cmdLines.join("\r\n"); // CRLF

  if (!commandQueue[sn]) commandQueue[sn] = [];
  commandQueue[sn].push(cmd);

  console.log(`✅ [ADD MEMBER] Queued for device ${sn}:`, cmd.replace(/\r\n/g, " | "));
  res.send(`User ${name} (PIN ${id}) queued for device ${sn} with command ID ${cmdId}`);
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

app.get("/helths", (req, res) => {
    res.send(`ok`);
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Fitrobit Protocol V4.8 Server online at http://localhost:${PORT}`);
});