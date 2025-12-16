const express = require('express');
const app = express();
const bodyParser = require('body-parser');

// Use text/plain parser because ZKTeco doesn't send JSON
app.use(bodyParser.text({ type: '*/*' }));

const PORT = 8081; // ADMS usually expects port 80 or 8081

/**
 * 1. HEARTBEAT / HANDSHAKE
 * The device pings this every few seconds to stay connected.
 */
app.get('/iclock/cdata', (req, res) => {
    const sn = req.query.SN;
    console.log(`[Heartbeat] Device SN: ${sn}`);

    // Standard ADMS response to keep device happy
    const response = [
        "GET OPTION FROM: " + sn,
        "Stamp=123456",
        "OpStamp=0",
        "ErrorDelay=60",
        "Delay=30",
        "ResLogDay=180",
        "TransTimes=00:00;23:59",
        "TransInterval=1",
        "TransFlag=1111111111",
    ].join("\n");

    res.header("Content-Type", "text/plain");
    res.send(response);
});

/**
 * 2. COMMAND PULLING
 * The device asks "Do you have any commands for me?" (Add user, Delete, etc.)
 */
app.get('/iclock/getrequest', (req, res) => {
    const sn = req.query.SN;
    
    // LOGIC: Check your database for pending commands for this 'sn'
    // Example: Add a new member with Expiry Date (EndTime)
    // Format: C:ID:DATA UPDATE user Pin=ID\tName=Name\tEndTime=YYYYMMDD
    
    const cmdId = Date.now(); // Unique ID for this command
    const memberId = "5001";
    const memberName = "John_Gym_Member";
    const expiry = "20251231"; // Dec 31, 2025

    // IMPORTANT: ZKTeco uses Tabs (\t) as separators, NOT spaces
    const command = `C:${cmdId}:DATA UPDATE user Pin=${memberId}\tName=${memberName}\tEndTime=${expiry}\tGroup=1`;

    console.log(`[Command Sent] To ${sn}: ${command}`);
    
    // If no commands, send "OK"
    // res.send("OK"); 
    
    res.send(command);
});

/**
 * 3. ATTENDANCE LOG RECEIVER
 * Device sends a POST when someone scans their face/finger.
 */
app.post('/iclock/cdata', (req, res) => {
    const sn = req.query.SN;
    const table = req.query.table; // Usually 'ATTLOG'
    const rawData = req.body;

    console.log(`[Log Received] From SN ${sn}: \n${rawData}`);

    // LOGIC: Parse rawData. 
    // Format is usually: PIN <TAB> DATETIME <TAB> STATUS ...
    // Store in your database here.

    res.send("OK");
});

/**
 * 4. COMMAND CONFIRMATION
 * Device tells you "I successfully added User 5001"
 */
app.post('/iclock/devicecmd', (req, res) => {
    const sn = req.query.SN;
    console.log(`[Device Result] From SN ${sn}: ${req.body}`);
    res.send("OK");
});

app.listen(PORT, () => {
    console.log(`Gym ADMS Server running on port ${PORT}`);
});