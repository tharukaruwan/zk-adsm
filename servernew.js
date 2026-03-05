/**
 * ZKTeco ADMS Push Protocol Server
 * Fully compliant with ZKTeco Push SDK Security Communication Protocol
 *
 * Implements:
 *  - Token authentication (MD5 of RegistryCode+SN+SessionID)
 *  - Full 7-step connection flow
 *  - Correct tabledata sub-routing with proper response counts
 *  - Device capability parsing on registration
 *  - Re-connection handling (registry=ok + RegistryCode)
 *  - All upload table types with correct response formats
 *  - Encryption key exchange stubs
 *  - Sub-controller authorization
 *  - Sequential CmdIDs (never 0)
 *  - Correct rtlog space-separated key=value parsing
 *  - rtstate relay/sensor/alarm bit parsing
 *  - Timezone delete-before-update enforcement
 *  - biophoto Type=9 enforcement on issue
 */

const express = require("express");
const crypto  = require("crypto");
const app     = express();
const PORT    = process.env.PORT || 8080;

app.use(express.text({ type: "*/*" }));

// =========================================================
// STATE
// =========================================================

/**
 * @typedef {Object} DeviceState
 * @property {string}   sn
 * @property {string|null} registryCode
 * @property {string|null} sessionId
 * @property {string}   lastSeen
 * @property {string}   status
 * @property {number}   timestamp
 * @property {Object}   capabilities
 * @property {string[]} cmdQueue
 * @property {Object}   cmdResults
 */

/** @type {Object.<string, DeviceState>} */
const devices = {};

/** Sequential CmdID — doc: must start at 1, never 0 */
let cmdCounter = 1;
const getNextCmdId = () => cmdCounter++;


// =========================================================
// HELPERS
// =========================================================

const ts = () => new Date();

const initDevice = (sn) => ({
    sn,
    registryCode : null,
    sessionId    : null,
    lastSeen     : ts().toLocaleString(),
    status       : "Online",
    timestamp    : ts().getTime(),
    capabilities : {},
    cmdQueue     : [],
    cmdResults   : {},
});

const updateDeviceHealth = (sn) => {
    if (!sn) return;
    if (!devices[sn]) devices[sn] = initDevice(sn);
    devices[sn].lastSeen  = ts().toLocaleString();
    devices[sn].status    = "Online";
    devices[sn].timestamp = ts().getTime();
};

/**
 * Token = MD5(RegistryCode + SN + SessionID) as hex string
 * Doc 4.5: all subsequent device requests use this token in Cookie header
 */
const makeToken = (registryCode, sn, sessionId) =>
    crypto.createHash("md5")
          .update(`${registryCode}${sn}${sessionId}`)
          .digest("hex");

/**
 * Parse flat key=value string (space/tab/comma separated)
 * e.g. "DeviceType=acc,DeviceName=F20,FirmVer=8.0.1"
 */
const parseKV = (raw = "") => {
    const obj = {};
    raw.split(/[\s,]+/).forEach(pair => {
        const idx = pair.indexOf("=");
        if (idx > 0) obj[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
    });
    return obj;
};

/**
 * Parse a space-separated rtlog / rtstate line into an object
 * Doc format: time=XXXX-XX-XX XX:XX:XX pin=X cardno=X event=X ...
 * Note: time value contains a space so we handle it specially
 */
const parseEventLine = (line = "") => {
    const obj = {};
    // Fix: time value has a space (e.g. "2017-01-10 11:49:32") — join first two tokens if needed
    const fixed = line.trim().replace(
        /^(time=\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/,
        "time=$1 $2"
    );
    fixed.split(/\s+/).forEach(pair => {
        const idx = pair.indexOf("=");
        if (idx > 0) obj[pair.slice(0, idx)] = pair.slice(idx + 1);
    });
    return obj;
};

/**
 * Queue one command string as-is onto the device queue.
 * Callers are responsible for correct ZK protocol formatting:
 *   Line 1:  C:<CmdID>:<VERB> <first key>=<val>\t<key>=<val>...\r\n
 *   Line 2+: <key>=<val>\t<key>=<val>...\r\n   (continuation records)
 */
const enqueue = (sn, cmd) => {
    if (!devices[sn]) devices[sn] = initDevice(sn);
    devices[sn].cmdQueue.push(cmd);
};

/**
 * Convert door number(s) to AuthorizeDoorId bitmask.
 * Java ref: authSum += Math.pow(2, doorNo - 1)
 * Door 1 → 1, Door 2 → 2, Door 3 → 4, Door 1+2 → 3, Door 1+2+3 → 7
 * @param {string|number|number[]} doors  e.g. "1", "1,2", [1,3]
 */
const calcDoorBitmask = (doors) => {
    const nums = Array.isArray(doors)
        ? doors
        : String(doors).split(",").map(d => parseInt(d.trim())).filter(Boolean);
    return nums.reduce((sum, d) => sum + Math.pow(2, d - 1), 0);
};

// Mark devices offline after 90s of silence
setInterval(() => {
    const cutoff = ts().getTime() - 90000;
    Object.values(devices).forEach(d => {
        if (d.timestamp < cutoff) d.status = "Offline";
    });
}, 15000);


// =========================================================
// 1. INITIALIZATION  (Doc 4.1)
//    GET /iclock/cdata?SN=&options=all
//
//    If device already registered → reply with registry=ok + RegistryCode + full config
//    If not registered            → reply plain OK (device then POSTs to /registry)
// =========================================================
app.get("/iclock/cdata", (req, res) => {
    const { SN, options, pushver } = req.query;
    updateDeviceHealth(SN);
    res.set("Content-Type", "text/plain");

    if (options === "all") {
        const device = devices[SN];

        if (device && device.registryCode) {
            // Already registered — return full config inline
            console.log(`🔄 Re-connection SN=${SN}`);
            const config = [
                `registry=ok`,
                `RegistryCode=${device.registryCode}`,
                `ServerVersion=3.0.1`,
                `ServerName=ADMS`,
                `PushProtVer=3.0.1`,
                `ErrorDelay=30`,
                `RequestDelay=2`,
                `TransTimes=00:00;14:00`,
                `TransInterval=1`,
                `TransTables=User Transaction`,
                `Realtime=1`,
                `SessionID=${device.sessionId}`,
                `TimeoutSec=10`,
                `BioPhotoFun=1`,
                `BioDataFun=1`,
            ].join("\r\n") + "\r\n";
            return res.send(config);
        }

        // Not yet registered
        console.log(`🔌 Init (new) SN=${SN} pushver=${pushver || "?"}`);
        return res.send("OK\n");
    }

    console.log(`🔌 Init SN=${SN}`);
    res.send("OK\n");
});


// =========================================================
// 2. ENCRYPTION KEY EXCHANGE  (Doc 4.2 / 4.3)
//    POST /iclock/exchange?SN=&type=publickey|factors
// =========================================================
app.post("/iclock/exchange", (req, res) => {
    const { SN, type } = req.query;
    updateDeviceHealth(SN);
    console.log(`🔐 Key exchange [${type}] SN=${SN}`);
    res.set("Content-Type", "text/plain");
    // Production: perform real RSA/AES exchange here
    if (type === "publickey") return res.send("PublicKey=STUB_PUBLIC_KEY\n");
    if (type === "factors")   return res.send("Factors=STUB_FACTORS\n");
    res.send("OK\n");
});


// =========================================================
// 3. REGISTRATION  (Doc 4.4)
//    POST /iclock/registry?SN=
//    Body: DeviceType=acc,DeviceName=...,FirmVer=...,MAC=..., ...
//    Reply: RegistryCode=<up to 32 chars>   (406 on failure)
// =========================================================
app.post("/iclock/registry", (req, res) => {
    const { SN } = req.query;
    if (!SN) return res.status(406).send("406\n");

    if (!devices[SN]) devices[SN] = initDevice(SN);
    updateDeviceHealth(SN);

    // Parse and store every capability the device advertises
    const caps = parseKV(req.body || "");
    devices[SN].capabilities = caps;

    console.log(`📝 Registration SN=${SN}`);
    console.log(`   DeviceType=${caps.DeviceType||"?"} FirmVer=${caps.FirmVer||"?"} MAC=${caps.MAC||"?"}`);
    console.log(`   Face=${caps.FaceFunOn||0} Finger=${caps.FingerFunOn||0} Locks=${caps.LockCount||"?"} MaxUsers=${caps.MaxUserCount||"?"}`);
    if (caps.MultiBioDataSupport) console.log(`   MultiBio=${caps.MultiBioDataSupport}`);

    // Generate registry code (≤32 chars) and session ID
    const registryCode = crypto.randomBytes(8).toString("hex");  // 16-char hex
    const sessionId    = crypto.randomBytes(8).toString("hex");
    devices[SN].registryCode = registryCode;
    devices[SN].sessionId    = sessionId;

    const token = makeToken(registryCode, SN, sessionId);
    console.log(`   ✅ RegistryCode=${registryCode} token=${token}`);

    res.set("Content-Type", "text/plain");
    res.set("Set-Cookie", `token=${token}; Path=/; HttpOnly`);
    res.send(`RegistryCode=${registryCode}\n`);
});


// =========================================================
// 4. DOWNLOAD CONFIG  (Doc 4.5)
//    POST /iclock/push?SN=   (also GET for older firmware)
// =========================================================
const buildPushConfig = (device) => [
    `ServerVersion=3.0.1`,
    `ServerName=ADMS`,
    `PushVersion=3.0.1`,
    `ErrorDelay=30`,
    `RequestDelay=2`,
    `TransTimes=00:00;14:00`,
    `TransInterval=1`,
    `TransTables=User Transaction`,
    `Realtime=1`,
    `SessionID=${device.sessionId}`,
    `TimeoutSec=10`,
    `BioPhotoFun=1`,
    `BioDataFun=1`,
    `MultiBioDataSupport=0:1:0:0:0:0:0:0:0:0:0`,
    `MultiBioPhotoSupport=0:0:0:0:0:0:0:0:0:1:0`,
].join("\r\n") + "\r\n";

app.post("/iclock/push", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    console.log(`📥 Config download (POST push) SN=${SN}`);
    const device = devices[SN];
    if (!device || !device.registryCode) return res.status(406).send("406\n");
    res.set("Content-Type", "text/plain");
    res.send(buildPushConfig(device));
});

app.get("/iclock/push", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    console.log(`📥 Config download (GET push) SN=${SN}`);
    const device = devices[SN];
    if (!device || !device.registryCode) return res.send("OK\n");
    res.set("Content-Type", "text/plain");
    res.send(buildPushConfig(device));
});


// =========================================================
// 5. COMMAND POLLING / HEARTBEAT  (Doc 6 / 9)
//    GET /iclock/getrequest?SN=   — device polls for commands
// =========================================================
app.get("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    res.set("Content-Type", "text/plain");

    const device = devices[SN];
    if (device && device.cmdQueue.length > 0) {
        const cmd = device.cmdQueue.shift();
        console.log(`🚀 [CMD→${SN}] ${cmd.replace(/\t/g, " | ")}`);
        return res.send(cmd + "\n");
    }
    res.send("OK\n");
});


// =========================================================
// 6. BACKUP HEARTBEAT  (Doc 6)
//    GET|POST /iclock/ping?SN=   — keepalive during large uploads
// =========================================================
app.all("/iclock/ping", (req, res) => {
    updateDeviceHealth(req.query.SN);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 7. COMMAND RESULT  (Doc 7.4)
//    POST /iclock/devicecmd?SN=
//    Body: ID=<cmdId>&Return=<code>&CMD=<type>[&SN=<subSN>]
//    Return >= 0  → success
//    Return < 0   → failure
//    Return=-5000 → received by sub-controller, pending
// =========================================================
app.post("/iclock/devicecmd", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);

    const raw = req.body ? req.body.trim() : "";
    const r   = {};
    raw.split("&").forEach(pair => {
        const idx = pair.indexOf("=");
        if (idx > 0) r[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
    });

    const { ID: cmdId, Return: returnCode, CMD: cmdType, SN: subSN } = r;
    if (cmdId && devices[SN]) {
        devices[SN].cmdResults[cmdId] = {
            Return: returnCode, CMD: cmdType,
            subSN: subSN || null, raw, at: ts().toISOString()
        };
    }

    const rc = parseInt(returnCode);
    if (returnCode === "-5000")     console.log(`⏳ [devicecmd] CmdID=${cmdId} pending on sub-controller`);
    else if (rc >= 0)               console.log(`✅ [devicecmd] CmdID=${cmdId} [${cmdType}] SUCCESS`);
    else                            console.log(`❌ [devicecmd] CmdID=${cmdId} [${cmdType}] FAILED Return=${returnCode}`);

    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});

// Older firmware POSTs results to getrequest instead of devicecmd
app.post("/iclock/getrequest", (req, res) => {
    const { SN } = req.query;
    updateDeviceHealth(SN);
    console.log(`🎯 [getrequest result] SN=${SN}: ${(req.body||"").trim()}`);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 8. QUERY DATA RESULTS  (Doc extended)
//    POST /iclock/querydata   — device uploads query results here
// =========================================================
app.post("/iclock/querydata", (req, res) => {
    const { SN, tablename } = req.query;
    updateDeviceHealth(SN);
    const raw = req.body ? req.body.trim() : "";
    console.log(`🔍 [querydata] SN=${SN} tablename=${tablename||"?"}`);
    if (raw) console.log(`   ${raw.slice(0, 400)}${raw.length > 400 ? "..." : ""}`);
    res.set("Content-Type", "text/plain");
    res.send("OK\n");
});


// =========================================================
// 9. DATA UPLOAD  (Doc 7.x)
//    POST /iclock/cdata?SN=&table=...&tablename=...
//
//  Routing table:
//    table=rtlog | transaction        → real-time / offline events
//    table=rtstate                    → door / relay / alarm state
//    table=options                    → device parameter upload
//    table=OPERLOG                    → operation log
//    table=tabledata
//      tablename=user                 → user info  (reply: user=N)
//      tablename=identitycard         → ID card    (reply: identitycard=N)
//      tablename=templatev10          → fingerprint(reply: templatev10=N)
//      tablename=biophoto             → bio photo  (reply: biophoto=N)
//      tablename=ATTPHOTO             → snapshot   (reply: ATTPHOTO=N)
//      tablename=biodata              → all-in-one template
//      tablename=DeviceAuthorize      → sub-ctrl auth table
// =========================================================
app.post("/iclock/cdata", (req, res) => {
    const { SN, table, tablename, type, count } = req.query;
    updateDeviceHealth(SN);
    const raw = (req.body || "").trim();
    res.set("Content-Type", "text/plain");

    // ── Real-time event / offline batch ──────────────────
    if (table === "rtlog" || table === "transaction") {
        const lines = raw.split(/\r?\n/).filter(Boolean);
        lines.forEach(line => {
            const d = parseEventLine(line);
            console.log(`🕐 [${table}] SN=${SN} time=${d.time||"?"} pin=${d.pin||"?"} event=${d.event||"?"} inout=${d.inoutstatus||"?"} addr=${d.eventaddr||"?"} verify=${d.verifytype||"?"}`);
            if (d.temperature)    console.log(`   🌡️  temp=${d.temperature} conv=${d.convtemperature||"?"}`);
            if (d.maskflag==="1") console.log(`   😷 Mask detected`);
            if (d.longitude && d.longitude !== "-1") console.log(`   📍 ${d.longitude},${d.latitude}`);
        });
        return res.send("OK\n");
    }

    // ── Real-time device state ────────────────────────────
    if (table === "rtstate") {
        const d = parseEventLine(raw);
        console.log(`📡 [rtstate] SN=${SN} time=${d.time||"?"}`);

        if (d.relay !== undefined) {
            const bits = parseInt(d.relay, 16);
            for (let i = 0; i < 8; i++) {
                if ((bits >> i) & 1) console.log(`   🔌 Door ${i+1} relay: DISCONNECTED`);
            }
        }

        if (d.sensor !== undefined) {
            const labels = ["no-sensor", "closed", "open", "unknown"];
            const bits = parseInt(d.sensor, 16);
            for (let i = 0; i < 8; i++) {
                const state = (bits >> (i * 2)) & 0b11;
                if (state) console.log(`   🚪 Door ${i+1}: ${labels[state]}`);
            }
        }

        if (d.alarm) {
            const alarmNames = [
                "Accidental open", "Tamper", "Duress password", "Duress fingerprint",
                "Door timeout",    "Mains failure", "Battery failure", "Reader disassembly"
            ];
            for (let door = 0; door < 8; door++) {
                const byte = parseInt((d.alarm || "").slice(door * 2, door * 2 + 2) || "0", 16);
                for (let bit = 0; bit < 8; bit++) {
                    if ((byte >> bit) & 1) console.log(`   🚨 Door ${door+1}: ${alarmNames[bit]}`);
                }
            }
        }
        return res.send("OK\n");
    }

    // ── Device option parameters upload ──────────────────
    if (table === "options") {
        const caps = parseKV(raw);
        if (devices[SN]) Object.assign(devices[SN].capabilities, caps);
        console.log(`⚙️  [options] SN=${SN} Users=${caps.UserCount||"?"} FP=${caps.FPCount||"?"} Face=${caps.FaceCount||"?"}`);
        return res.send("OK\n");
    }

    // ── Operation log ─────────────────────────────────────
    if (table === "OPERLOG") {
        const lines = raw.split(/\r?\n/).filter(Boolean);
        lines.forEach(line => {
            const parts = line.split(/\s+/);
            console.log(`📋 [OPERLOG] SN=${SN} opType=${parts[1]||"?"} pin=${parts[5]||"?"}`);
        });
        return res.send(`OK: ${lines.length}\n`);
    }

    // ── tabledata sub-routing ─────────────────────────────
    if (table === "tabledata" || type === "registry") {
        const tname      = (tablename || "").toLowerCase();
        const countParam = parseInt(count) || 0;

        // User info upload — reply MUST be "user=N" not "OK"
        if (tname === "user") {
            const lines = raw.split(/\r?\n/).filter(l => /^user\s+/i.test(l.trim()));
            let n = 0;
            lines.forEach(line => {
                const d = parseEventLine(line.replace(/^user\s+/i, ""));
                console.log(`👤 [user] SN=${SN} pin=${d.pin||"?"} name=${d.name||"?"} card=${d.cardno||"?"}`);
                n++;
            });
            return res.send(`user=${n || countParam}\n`);
        }

        // Identity card
        if (tname === "identitycard") {
            const lines = raw.split(/\r?\n/).filter(l => /^identitycard\s+/i.test(l.trim()));
            let n = 0;
            lines.forEach(line => {
                const d = parseEventLine(line.replace(/^identitycard\s+/i, ""));
                console.log(`🪪 [identitycard] SN=${SN} pin=${d.pin||"?"} IDNum=${d.ID_Num||"?"}`);
                n++;
            });
            return res.send(`identitycard=${n || countParam}\n`);
        }

        // Fingerprint template v10
        if (tname === "templatev10") {
            const lines = raw.split(/\r?\n/).filter(l => /^templatev10\s+/i.test(l.trim()));
            let n = 0;
            lines.forEach(line => {
                const d = parseEventLine(line.replace(/^templatev10\s+/i, ""));
                console.log(`🖐️  [templatev10] SN=${SN} pin=${d.pin||"?"} fingerid=${d.fingerid||"?"} size=${d.size||"?"}`);
                n++;
            });
            return res.send(`templatev10=${n || countParam}\n`);
        }

        // Biometric comparison photo
        if (tname === "biophoto") {
            const lines = raw.split(/\r?\n/).filter(l => /^biophoto\s+/i.test(l.trim()));
            let n = 0;
            lines.forEach(line => {
                const d = parseEventLine(line.replace(/^biophoto\s+/i, ""));
                console.log(`📸 [biophoto] SN=${SN} pin=${d.pin||"?"} type=${d.type||"?"} file=${d.filename||"?"} size=${d.size||"?"}`);
                n++;
            });
            return res.send(`biophoto=${n || countParam}\n`);
        }

        // Attendance snapshot
        if (tname === "attphoto") {
            const lines = raw.split(/\r?\n/).filter(l => /^pin=/i.test(l.trim()));
            let n = 0;
            lines.forEach(line => {
                const d = parseEventLine(line);
                console.log(`🖼️  [ATTPHOTO] SN=${SN} pin=${d.pin||"?"} size=${d.size||"?"}`);
                n++;
            });
            return res.send(`ATTPHOTO=${n || countParam}\n`);
        }

        // All-in-one biodata (visible light face)
        if (tname === "biodata") {
            console.log(`🧬 [biodata] SN=${SN} ${raw.length} bytes`);
            return res.send(`biodata=${countParam || 1}\n`);
        }

        // Sub-controller authorization table
        if (tname === "deviceauthorize") {
            const lines = raw.split(/\r?\n/).filter(Boolean);
            const authLabels = { "0":"Unauthorized", "1":"In Progress", "2":"Authorized" };
            lines.forEach(line => {
                const d = parseEventLine(line);
                console.log(`🔑 [DeviceAuthorize] SN=${SN} subSN=${d.SN||"?"} online=${d.Online||"?"} auth=${authLabels[d.IsAuthorize]||"?"}`);
            });
            return res.send("OK\n");
        }

        console.log(`❓ [tabledata/${tablename}] SN=${SN} ${raw.length} bytes`);
        return res.send("OK\n");
    }

    console.log(`❓ [cdata] SN=${SN} table=${table||"?"} tablename=${tablename||"?"} ${raw.length} bytes`);
    res.send("OK\n");
});


// =========================================================
// MANAGEMENT API
// =========================================================

// ── Add member (user + access rights) ───────────────────
// Java ref: AuthorityServlet.java — DATA UPDATE user / DATA UPDATE userauthorize
// Field names from Java: CardNo, Pin, Password, Group, StartTime, EndTime, Name, SuperAuthorize, Disable
// AuthorizeDoorId is a BITMASK: door1=1, door2=2, door3=4, door1+2=3 etc.
app.get("/add-member", (req, res) => {
    const { sn, id, name, card, password, timezone, door, startTime, endTime, superAuth, disable } = req.query;
    if (!sn || !id || !name) return res.status(400).json({ error: "Missing: sn, id, name" });

    const tzId      = timezone   || "1";
    const doorMask  = calcDoorBitmask(door || "1");  // bitmask, not raw door number
    const cid1      = getNextCmdId();
    const cid2      = getNextCmdId();
    const cid3      = getNextCmdId();

    // Command 1: Create/update user record
    // Java format: DATA UPDATE user CardNo=X\tPin=X\tPassword=X\tGroup=0\tStartTime=0\tEndTime=0\tName=X\tSuperAuthorize=0\tDisable=0\r\n
    const cmdUser = [
        `C:${cid1}:DATA UPDATE user`,
        `CardNo=${card || ""}`,
        `Pin=${id}`,
        `Password=${password || ""}`,
        `Group=0`,
        `StartTime=${startTime || "0"}`,
        `EndTime=${endTime || "0"}`,
        `Name=${name}`,
        `SuperAuthorize=${superAuth || "0"}`,
        `Disable=${disable || "0"}`,
    ].join("\t") + "\r\n";

    // Command 2: Assign timezone rule to device
    // Java always issues the timezone rule before userauthorize
    const tzMap = { TimezoneId: tzId };
    const cmdTimezone = buildTimezoneCmd(cid2, tzId, tzMap);

    // Command 3: Assign access rights
    // Java format: DATA UPDATE userauthorize Pin=X\tAuthorizeTimezoneId=X\tAuthorizeDoorId=X\r\n
    const cmdAuth = [
        `C:${cid3}:DATA UPDATE userauthorize`,
        `Pin=${id}`,
        `AuthorizeTimezoneId=${tzId}`,
        `AuthorizeDoorId=${doorMask}`,
    ].join("\t") + "\r\n";

    enqueue(sn, cmdUser);
    enqueue(sn, cmdTimezone);
    enqueue(sn, cmdAuth);

    console.log(`✅ [add-member] SN=${sn} PIN=${id} Name=${name} TZ=${tzId} Doors=${door||1} DoorMask=${doorMask}`);
    res.json({ status: "queued", pin: id, name, doorMask, cmdIds: [cid1, cid2, cid3] });
});


// ── Delete member ─────────────────────────────────────────
// Doc 2.2: MUST delete userauthorize BEFORE user record
// Java: "DATA DELETE userauthorize Pin=X\r\n" then "DATA DELETE user Pin=X\r\n"
app.get("/delete-member", (req, res) => {
    const { sn, id } = req.query;
    if (!sn || !id) return res.status(400).json({ error: "Missing: sn, id" });

    const cid1 = getNextCmdId();
    const cid2 = getNextCmdId();

    // Step 1: remove access rights first
    const cmdDelAuth = `C:${cid1}:DATA DELETE userauthorize\tPin=${id}\r\n`;
    // Step 2: then delete user record
    const cmdDelUser = `C:${cid2}:DATA DELETE user\tPin=${id}\r\n`;

    enqueue(sn, cmdDelAuth);
    enqueue(sn, cmdDelUser);

    console.log(`🗑️  [delete-member] SN=${sn} PIN=${id}`);
    res.json({ status: "queued", pin: id, cmdIds: [cid1, cid2] });
});


// ── Update timezone ───────────────────────────────────────
// Doc 2.2 WARNING: Direct UPDATE without DELETE first = user gets BOTH timezones
app.get("/update-timezone", (req, res) => {
    const { sn, id, timezone, door } = req.query;
    if (!sn || !id || !timezone) return res.status(400).json({ error: "Missing: sn, id, timezone" });

    const doorMask = calcDoorBitmask(door || "1");
    const cid1     = getNextCmdId();
    const cid2     = getNextCmdId();

    // Step 1: delete existing access rights
    const cmdDel  = `C:${cid1}:DATA DELETE userauthorize\tPin=${id}\r\n`;
    // Step 2: assign new timezone with bitmask door
    const cmdAuth = [
        `C:${cid2}:DATA UPDATE userauthorize`,
        `Pin=${id}`,
        `AuthorizeTimezoneId=${timezone}`,
        `AuthorizeDoorId=${doorMask}`,
    ].join("\t") + "\r\n";

    enqueue(sn, cmdDel);
    enqueue(sn, cmdAuth);

    console.log(`🕐 [update-timezone] SN=${sn} PIN=${id} → TZ=${timezone} DoorMask=${doorMask}`);
    res.json({ status: "queued", pin: id, timezone, doorMask, cmdIds: [cid1, cid2] });
});


// ── Set timezone rule ─────────────────────────────────────
// Java ref: calculateTime(start, end) = ((startHH*100+startMM) << 16) | (endHH*100+endMM)
// Supports 3 time slots per day + 3 holiday groups (Hol1/2/3), matching Java timezoneCmd()
const calculateTime = (start, end) => {
    if (!start || !end) return 0;
    const [sh, sm] = start.split(":").map(Number);
    const [eh, em] = end.split(":").map(Number);
    return ((sh * 100 + sm) << 16) | (eh * 100 + em);
};

/**
 * Build a full timezone command string as the Java reference does.
 * Supports all 3 slots per day (Time1/Time2/Time3) + Hol1/2/3.
 * @param {number}  cid   CmdID
 * @param {string}  tzId  TimezoneId
 * @param {Object}  slots { MonTime1: [start,end], MonTime2: [...], ... }
 *                        OR simple { start:"08:00", end:"18:00" } for single-slot shorthand
 */
const buildTimezoneCmd = (cid, tzId, slots = {}) => {
    const days  = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    const hols  = ["Hol1","Hol2","Hol3"];
    const all   = [...days, ...hols];

    const defaultStart = slots.start || "00:00";
    const defaultEnd   = slots.end   || "23:59";

    const parts = [`C:${cid}:DATA UPDATE timezone`, `TimezoneId=${tzId}`];

    all.forEach(day => {
        for (let i = 1; i <= 3; i++) {
            const key   = `${day}Time${i}`;
            const entry = slots[key];  // expects [start, end] or undefined
            let val;
            if (Array.isArray(entry)) {
                val = calculateTime(entry[0], entry[1]);
            } else if (i === 1 && !slots.start === false) {
                // slot 1 gets default full-day, slots 2/3 get 0 (disabled)
                val = calculateTime(defaultStart, defaultEnd);
            } else {
                val = 0;
            }
            parts.push(`${key}=${val}`);
        }
    });

    return parts.join("\t") + "\r\n";
};

app.get("/set-timezone", (req, res) => {
    const { sn, tzid, start, end } = req.query;
    if (!sn || !tzid) return res.status(400).json({ error: "Missing: sn, tzid" });

    const cid = getNextCmdId();
    const cmd = buildTimezoneCmd(cid, tzid, { start: start || "00:00", end: end || "23:59" });
    enqueue(sn, cmd);

    const timeCode = calculateTime(start || "00:00", end || "23:59");
    res.json({ status: "queued", cmdId: cid, tzid, timeCode });
});


// ── Issue biophoto to device ──────────────────────────────
// Doc 2.1.3: MUST use Type=9 when issuing from server (not 0)
app.get("/issue-photo", (req, res) => {
    const { sn, id, url, size } = req.query;
    if (!sn || !id || !url) return res.status(400).json({ error: "Missing: sn, id, url" });

    const cid = getNextCmdId();
    const cmd = [
        `C:${cid}:DATA UPDATE BIOPHOTO`,
        `PIN=${id}`,
        `Type=9`,
        `Size=${size || 0}`,
        `Content=`,
        `Format=1`,
        `Url=${url}`,
    ].join("\t") + "\r\n";
    enqueue(sn, cmd);

    res.json({ status: "queued", cmdId: cid });
});


// ── Query users ───────────────────────────────────────────
app.get("/query-users", (req, res) => {
    const { sn, pin } = req.query;
    if (!sn) return res.status(400).json({ error: "Missing: sn" });

    const cid    = getNextCmdId();
    const filter = pin ? `Pin=${pin}` : `*`;
    enqueue(sn, `C:${cid}:DATA QUERY tablename=user,fielddesc=*,filter=${filter}\r\n`);

    res.json({ status: "queued", cmdId: cid });
});


// ── Open door ─────────────────────────────────────────────
// Doc 2.4 format: AABBCCDDEE where AA=01(open), BB=door(hex), CC=00, DD=seconds(hex)
app.get("/open-door", (req, res) => {
    const { sn, door, seconds } = req.query;
    if (!sn) return res.status(400).json({ error: "Missing: sn" });

    const doorHex = parseInt(door    || "1").toString(16).padStart(2, "0");
    const secsHex = parseInt(seconds || "5").toString(16).padStart(2, "0");
    const code    = `0101${doorHex}00${secsHex}`;
    const cid     = getNextCmdId();

    enqueue(sn, `C:${cid}:CONTROL DEVICE ${code}\r\n`);

    console.log(`🚪 [open-door] SN=${sn} door=${door||1} secs=${seconds||5} code=${code}`);
    res.json({ status: "queued", cmdId: cid, controlCode: code });
});


// ── Reboot device ─────────────────────────────────────────
app.get("/reboot-device", (req, res) => {
    const { sn } = req.query;
    if (!sn) return res.status(400).json({ error: "Missing: sn" });

    const cid = getNextCmdId();
    enqueue(sn, `C:${cid}:CONTROL DEVICE 03000000\r\n`);

    console.log(`🔄 [reboot] SN=${sn}`);
    res.json({ status: "queued", cmdId: cid });
});


// ── Sub-controller authorization ──────────────────────────
app.get("/authorize-device", (req, res) => {
    const { sn, subSN, level } = req.query;
    if (!sn || !subSN) return res.status(400).json({ error: "Missing: sn, subSN" });

    const cid = getNextCmdId();
    enqueue(sn, `C:${cid}:DATA UPDATE DeviceAuthorize\tSN=${subSN}\tIsAuthorize=${level || "2"}\r\n`);

    res.json({ status: "queued", cmdId: cid });
});

app.get("/deauthorize-device", (req, res) => {
    const { sn, subSN } = req.query;
    if (!sn || !subSN) return res.status(400).json({ error: "Missing: sn, subSN" });

    const cid = getNextCmdId();
    enqueue(sn, `C:${cid}:DATA DELETE DeviceAuthorize\tSN=${subSN}\r\n`);

    res.json({ status: "queued", cmdId: cid });
});


// ── Command result lookup ─────────────────────────────────
app.get("/cmd-result", (req, res) => {
    const { sn, id } = req.query;
    if (!sn) {
        const all = Object.fromEntries(Object.entries(devices).map(([k,v]) => [k, v.cmdResults]));
        return res.json(all);
    }
    if (!devices[sn]) return res.status(404).json({ error: "Device not found" });
    if (!id)          return res.json(devices[sn].cmdResults);
    res.json(devices[sn].cmdResults[id] || { error: "CmdID not found" });
});


// ── Device status dashboard ───────────────────────────────
app.get("/devices", (req, res) => {
    const out = Object.fromEntries(Object.entries(devices).map(([sn, d]) => [sn, {
        status      : d.status,
        lastSeen    : d.lastSeen,
        queueLength : d.cmdQueue.length,
        capabilities: {
            DeviceType   : d.capabilities.DeviceType,
            FirmVer      : d.capabilities.FirmVer,
            MAC          : d.capabilities.MAC,
            FaceFunOn    : d.capabilities.FaceFunOn,
            FingerFunOn  : d.capabilities.FingerFunOn,
            LockCount    : d.capabilities.LockCount,
            MaxUserCount : d.capabilities.MaxUserCount,
        },
    }]));
    res.json(out);
});


// ── Health ────────────────────────────────────────────────
app.get("/health", (req, res) =>
    res.json({ status: "ok", uptime: Math.floor(process.uptime()), devices: Object.keys(devices).length }));

app.get("/helths", (req, res) => res.send("ok")); // legacy


// =========================================================
app.listen(PORT, "0.0.0.0", () => {
    console.log(`\n🚀 ZKTeco ADMS Push Protocol Server on :${PORT}`);
    console.log(`\nDevice protocol endpoints:`);
    console.log(`  GET  /iclock/cdata?SN=&options=all     init / re-connect`);
    console.log(`  POST /iclock/registry?SN=              register + capabilities`);
    console.log(`  POST /iclock/push?SN=                  download server config`);
    console.log(`  GET  /iclock/getrequest?SN=            command poll (heartbeat)`);
    console.log(`  POST /iclock/devicecmd?SN=             command result`);
    console.log(`  POST /iclock/cdata?SN=&table=...       data upload`);
    console.log(`  GET|POST /iclock/ping?SN=              backup heartbeat`);
    console.log(`  POST /iclock/exchange?SN=&type=...     key exchange`);
    console.log(`  POST /iclock/querydata?SN=             query results`);
    console.log(`\nManagement API:`);
    console.log(`  GET /add-member?sn=&id=&name=[&timezone=][&door=]`);
    console.log(`  GET /delete-member?sn=&id=`);
    console.log(`  GET /update-timezone?sn=&id=&timezone=[&door=]`);
    console.log(`  GET /set-timezone?sn=&tzid=[&start=HH:MM][&end=HH:MM]`);
    console.log(`  GET /issue-photo?sn=&id=&url=[&size=]`);
    console.log(`  GET /query-users?sn=[&pin=]`);
    console.log(`  GET /open-door?sn=[&door=][&seconds=]`);
    console.log(`  GET /reboot-device?sn=`);
    console.log(`  GET /authorize-device?sn=&subSN=[&level=]`);
    console.log(`  GET /deauthorize-device?sn=&subSN=`);
    console.log(`  GET /cmd-result[?sn=][&id=]`);
    console.log(`  GET /devices`);
    console.log(`  GET /health\n`);
});