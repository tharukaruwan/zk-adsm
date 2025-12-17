const express = require("express");
const app = express();
const PORT = 8081;

app.use(express.text({ type: "*/*" }));

let commandQueue = {};  

// Helper to add commands to queue with unique ID (C:ID:...)
const queueCommand = (sn, commandText) => {
    const cmdId = Math.floor(Math.random() * 10000);
    const fullCmd = `C:${cmdId}:${commandText}`;
    if (!commandQueue[sn]) commandQueue[sn] = [];
    commandQueue[sn].push(fullCmd);
    return cmdId;
};

// ---------------------------------------------------------
// CRUD API ENDPOINTS
// ---------------------------------------------------------

// 1. CREATE & UPDATE (Same command in PUSH protocol)
app.get("/user/upsert", (req, res) => {
    const { sn, id, name, card = "", pri = "0" } = req.query;
    if (!sn || !id) return res.status(400).send("Missing sn or id");

    // Table: USERINFO, Separator: TAB (\t)
    const cmdBody = [
        `DATA UPDATE USERINFO PIN=${id}`,
        `Name=${name || ''}`,
        `Pri=${pri}`,
        `Passwd=`,
        `Card=${card}`,
        `Grp=1`,
        `TZ=0000000000000000`,
        `Verify=0`
    ].join("\t");

    const cmdId = queueCommand(sn, cmdBody);
    console.log(`👤 UPSERT QUEUED: ${name} (ID: ${id}) - CmdID: ${cmdId}`);
    res.send({ status: "Queued", cmdId, pin: id });
});

// 2. READ (Query from device)
app.get("/user/query", (req, res) => {
    const { sn, id } = req.query;
    if (!sn) return res.status(400).send("Missing sn");

    // If ID is provided, query specific PIN, else query all
    const filter = id ? ` PIN=${id}` : "";
    const cmdId = queueCommand(sn, `DATA QUERY USERINFO${filter}`);
    
    console.log(`🔍 QUERY QUEUED for ${sn} - CmdID: ${cmdId}`);
    res.send({ status: "Query Queued", cmdId });
});

// 3. DELETE (Single User)
app.get("/user/delete", (req, res) => {
    const { sn, id } = req.query;
    if (!sn || !id) return res.status(400).send("Missing sn or id");

    const cmdId = queueCommand(sn, `DATA DELETE USERINFO PIN=${id}`);
    
    console.log(`🗑️ DELETE QUEUED: ID ${id} - CmdID: ${cmdId}`);
    res.send({ status: "Delete Queued", cmdId, pin: id });
});

// 4. CLEAR (Delete ALL users from device)
app.get("/user/clear-all", (req, res) => {
    const { sn } = req.query;
    if (!sn) return res.status(400).send("Missing sn");

    const cmdId = queueCommand(sn, `CLEAR USERINFO`);
    
    console.log(`⚠️ CLEAR ALL USERS QUEUED for ${sn}`);
    res.send({ status: "Clear All Queued", cmdId });
});

// ---------------------------------------------------------
// DEVICE COMMUNICATION HANDLERS (Standard)
// ---------------------------------------------------------

app.get("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    res.set("Content-Type", "text/plain");

    if (commandQueue[SN] && commandQueue[SN].length > 0) {
        const cmd = commandQueue[SN].shift();
        console.log(`🚀 Sending to Device ${SN}: ${cmd}`);
        return res.send(cmd + "\n");
    }
    res.send("OK\n");
});

app.post("/iclock/getrequest", (req, res) => {
    console.log(`🎯 Device Result: ${req.body.trim()}`);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// Handshake for Blinking Yellow Icon
app.get("/iclock/cdata", (req, res) => {
    const { SN, options } = req.query;
    if (options === "all") {
        const now = Math.floor(Date.now() / 1000);
        const config = `GET OPTION FROM: ${SN}\r\nStamp=${now}\r\nOpStamp=${now}\r\nErrorDelay=60\r\nDelay=30\r\nTransInterval=1\r\nTransFlag=1111000000\r\nRealtime=1\r\nEncrypt=0\r\nServerVer=3.4.1\r\nPushVer=3.2.1\r\nADMSVer=1.0.0\r\nSessionID=${now}\r\nCompatibility=1\r\n`;
        res.set("Content-Type", "text/plain");
        return res.send(config);
    }
    res.send("OK\n");
});

app.post("/iclock/registry", (req, res) => {
    res.set("Content-Type", "text/plain");
    res.send("RegistryCode=OK\n"); 
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 ZK CRUD Server online on port ${PORT}`);
});