const express = require('express');
const session = require('express-session');
const msal = require('@azure/msal-node');
const multer = require('multer');
const sql = require('mssql');
const { DefaultAzureCredential } = require('@azure/identity');
const { BlobServiceClient } = require('@azure/storage-blob');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const upload = multer({ storage: multer.memoryStorage() }); // Temporarily buffer uploaded files in memory

// ==========================================
// 1. STATE & SECURITY SESSION CONFIGURATION
// ==========================================

app.use(session({
    secret: 'portfolio-secure-session-key', // Change this to a random string in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false // Set to true if deploying to HTTPS behind Front Door later
    }
}));

// Serve static assets from your local 'public' project root directory
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ==========================================
// 2. AZURE INFRASTRUCTURE CREDENTIALS SETUP
// ==========================================

// Uses your App Service Managed Identity
////////const azureCredential = new DefaultAzureCredential();

// Read physical infrastructure names dynamically from Web App Environment Variables
////////const storageAccountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
////////const sqlServerName = process.env.AZURE_SQL_SERVER_NAME;
////////const sqlDatabaseName = process.env.AZURE_DATABASE_NAME;

// Initialize East US Blob Storage Service Client
//////const blobServiceClient = new BlobServiceClient(
//////    `https://${storageAccountName}.blob.core.windows.net`,
//////    azureCredential
/////);

// Initialize Central US Azure SQL Connection Pool configuration
//const sqlConfig = {
//    server: `${sqlServerName}.database.windows.net`,
//    database: sqlDatabaseName,
//    options: {
//        encrypt: true,
//        authentication: {
//            type: 'azure-active-directory-msi-app-service'
//        }
//    }
//};
// Dynamic Connection Function to grab tokens before connecting
//////async function initializeDatabaseConnection() {
//////    try {
//////        console.log("Requesting access token for Azure SQL over the VNet...");
        
        // 1. Fetch a token explicitly scoped for Azure SQL Database
//////        const sqlTokenResult = await azureCredential.getToken("https://windows.net");
        
        // 2. Inject that token string straight into your driver settings
//////        const sqlConfig = {
 //           server: `${sqlServerName}.database.windows.net`,
//////            database: sqlDatabaseName,
//////            token: sqlTokenResult.token, // 🔑 Drops your identity token directly into the login packet!
//////            options: {
//////                encrypt: true,
//////                trustServerCertificate: false // Standard security for cloud servers
//////            }
//////        };

        // 3. Connect the pool using the token credentials
//////        dbPool = await sql.connect(sqlConfig);
//////        console.log("🎉 SUCCESS: Connected to Azure SQL privately via Managed Identity!");
//////    } catch (err) {
/////        console.error("Database connection failure:", err.message);
/////    }
/////}

// Execute the connection routine at server startup
/////let dbPool;
/////initializeDatabaseConnection();

// ==========================================
// 2. AZURE INFRASTRUCTURE CREDENTIALS SETUP 
// ==========================================

/// Uses your App Service Managed Identity

const azureCredential = new DefaultAzureCredential();

// // Read Azure infrastructure names from App Service Environment Variables
const storageAccountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
const sqlServerName = process.env.AZURE_SQL_SERVER_NAME;
const sqlDatabaseName = process.env.AZURE_DATABASE_NAME;

// Initialize Blob Storage
const blobServiceClient = new BlobServiceClient(
    `https://${storageAccountName}.blob.core.windows.net`,
    azureCredential
);

// Azure SQL connection
async function initializeDatabaseConnection() {
    try {
        console.log("Requesting access token for Azure SQL...");

        // Request an Azure SQL access token
        const sqlTokenResult = await azureCredential.getToken(
            "https://database.windows.net/.default"
        );

        if (!sqlTokenResult || !sqlTokenResult.token) {
            throw new Error("Failed to obtain Azure SQL access token.");
        }

        console.log("Azure SQL access token acquired.");
        const tokenParts = sqlTokenResult.token.split('.');

        if (tokenParts.length === 3) {
        const tokenPayload = JSON.parse(
        Buffer.from(tokenParts[1], 'base64url').toString('utf8')
        );

        console.log("SQL token audience:", tokenPayload.aud);
        console.log("SQL token tenant:", tokenPayload.tid);
        console.log("SQL token object ID:", tokenPayload.oid);
}

        const sqlConfig = {
            server: `${sqlServerName}.database.windows.net`,
            database: sqlDatabaseName,

            authentication: {
                type: "azure-active-directory-access-token",
                options: {
                    token: sqlTokenResult.token
                }
            },

            options: {
                encrypt: true,
                trustServerCertificate: false
            }
        };

        dbPool = await sql.connect(sqlConfig);

        console.log(
            "SUCCESS: Connected to Azure SQL using Managed Identity!"
        );

        return dbPool;

    } catch (err) {
        console.error(
            "Database connection failure:",
            err.message
        );
    }
}

let dbPool;

initializeDatabaseConnection();


// Initialize M365 Entra ID Multi-Tenant Authentication Client
const msalConfig = {
    auth: {
        clientId: process.env.Entra_ClientId,
        authority: `https://microsoftonline.com`,
        clientSecret: process.env.Entra_ClientSecret
    }
};

const cca = new msal.ConfidentialClientApplication(msalConfig);



// ==========================================
// 3. SECURITY GATE MIDDLEWARE (RBAC)
// ==========================================

async function authorizeUserRole(req, res, next) {
    try {
        // Authenticated Gate Check
        if (!req.session.isAuthenticated) {
            return res.redirect('/login.html');
        }

        const userOID = req.session.userObjectID;
        const userEmail = req.session.userEmail;

        // Query your AppUsers table over the private VNet
        const queryRequest = new sql.Request(dbPool);

        queryRequest.input('oid', sql.VarChar, userOID);

        const dbResult = await queryRequest.query(
            "SELECT UserRole FROM AppUsers WHERE UserObjectID = @oid"
        );

        // If the user doesn't exist in your SQL database yet,
        // automatically register them as a default 'Student'
        if (dbResult.recordset.length === 0) {
            const insertRequest = new sql.Request(dbPool);

            insertRequest.input('oid', sql.VarChar, userOID);
            insertRequest.input('email', sql.VarChar, userEmail);

            await insertRequest.query(
                "INSERT INTO AppUsers (UserObjectID, UserEmail, UserRole) VALUES (@oid, @email, 'Student')"
            );

            req.userRole = 'Student';
        } else {
            // Extract the user's role from the SQL database
            req.userRole = dbResult.recordset[0].UserRole;
        }

        next();

    } catch (error) {
        console.error(
            "Authorization middleware error:",
            error.message
        );

        res.status(500).send(
            "Internal Security Mapping Failure."
        );
    }
}

// ==========================================
// 4. ROUTING & CONTROLLERS
// ==========================================

// --- THE LOGIN ROUTE INTERCEPTOR ---

app.get('/auth/login', async (req, res) => {

    const authCodeUrlParameters = {
        scopes: ["user.read"],

        // When user authenticates, bounce them to your callback landing zone
        redirectUri: "https://azurewebsites.net"
    };

    try {
        const response = await cca.getAuthCodeUrl(
            authCodeUrlParameters
        );

        res.redirect(response);

    } catch (error) {
        res.status(500).send(
            "Error generating Entra ID challenge payload."
        );
    }
});

// --- THE ENTRA ID LANDING ZONE ---

app.get('/auth/callback', async (req, res) => {

    const tokenRequest = {
        code: req.query.code,
        scopes: ["user.read"],
        redirectUri: "https://azurewebsites.net"
    };

    try {
        const authResult = await cca.acquireTokenByCode(
            tokenRequest
        );

        const decodedToken = jwt.decode(
            authResult.idToken
        );

        // Commit core identification variables directly into the session cookie
        req.session.isAuthenticated = true;
        req.session.userObjectID = decodedToken.oid;
        req.session.userEmail =
            decodedToken.preferred_username ||
            decodedToken.email;

        console.log(
            `Authentication verified for identity: ${req.session.userEmail}`
        );

        // Forward the user to the dynamic router entry checkpoint
        res.redirect('/dashboard');

    } catch (error) {
        console.error(
            "Token acquisition roadblock:",
            error.message
        );

        res.status(500).send(
            "Identity validation handshake broken."
        );
    }
});

// --- THE CENTRAL DYNAMIC DASHBOARD ENTRY ROUTER ---

app.get(
    '/dashboard',
    authorizeUserRole,
    (req, res) => {

        // Branch browser rendering experiences based entirely
        // on their SQL UserRole value
        if (req.userRole === 'Admin') {

            res.sendFile(
                path.join(
                    __dirname,
                    'public',
                    'admin-gallery.html'
                )
            );

        } else if (req.userRole === 'Student') {

            res.sendFile(
                path.join(
                    __dirname,
                    'public',
                    'upload.html'
                )
            );

        } else {

            res.status(403).send(
                "Your explicit database scope tier is unsupported."
            );
        }
    }
);

// --- THE STUDENT ASSET SUBMISSION SYSTEM ---

app.post(
    '/submit-portfolio',
    authorizeUserRole,
    upload.single('studentFile'),
    async (req, res) => {

        try {

            // Double-check security bounds
            if (
                req.userRole !== 'Student' &&
                req.userRole !== 'Admin'
            ) {
                return res.status(403).send(
                    "Forbidden: Only portfolio holders can upload files."
                );
            }

            const fileDescription = req.body.description;
            const filePayload = req.file;
            const studentOID = req.session.userObjectID;

            if (!filePayload || !fileDescription) {
                return res.status(400).send(
                    "Required portfolio metadata or payload structural assets are missing."
                );
            }

            // Phase 1: Stream the raw multi-media payload privately to East US Blob Container
            const containerClient =
                blobServiceClient.getContainerClient(
                    "student-assets"
                );

            await containerClient.createIfNotExists({
                accessType: 'blob'
            });

            const uniqueBlobName =
                `${Date.now()}-${studentOID}-${filePayload.originalname}`;

            const blockBlobClient =
                containerClient.getBlockBlobClient(
                    uniqueBlobName
                );

            console.log(
                "Uploading file payload straight into Blob Storage via Managed Identity..."
            );

            await blockBlobClient.upload(
                filePayload.buffer,
                filePayload.buffer.length
            );

            const savedBlobURL = blockBlobClient.url;

            // Phase 2: Log file text descriptions and URL link inside Azure SQL via VNet
            console.log(
                "Syncing blob text metadata tracking rows into Azure SQL..."
            );

            const queryRequest = new sql.Request(dbPool);

            queryRequest.input(
                'studentOid',
                sql.VarChar,
                studentOID
            );

            queryRequest.input(
                'desc',
                sql.NVarChar,
                fileDescription
            );

            queryRequest.input(
                'origName',
                sql.NVarChar,
                filePayload.originalname
            );

            queryRequest.input(
                'blobUrl',
                sql.NVarChar,
                savedBlobURL
            );

            await queryRequest.query(`
                INSERT INTO StudentSubmissions
                (
                    StudentObjectID,
                    FileDescription,
                    OriginalFileName,
                    BlobStorageURL
                )
                VALUES
                (
                    @studentOid,
                    @desc,
                    @origName,
                    @blobUrl
                )
            `);

            res.status(200).send(
                `<h3>Success! Your portfolio item has been saved to the database.</h3>
                <br>
                <a href="/dashboard">Back to Dashboard</a>`
            );

        } catch (error) {

            console.error(
                "Decoupled pipeline structural fault:",
                error.message
            );

            res.status(500).send(
                "Critical server infrastructure syncing exception occurred."
            );
        }
    }
);

// --- THE ADMIN GLOBAL SEARCH & FILTER REST API ---

app.get(
    '/admin/view-all',
    authorizeUserRole,
    async (req, res) => {

        if (req.userRole !== 'Admin') {
            return res.status(403).send(
                "Access Denied: Administrative Clearance Required."
            );
        }

        try {

            const searchTerm =
                req.query.search || '';

            const queryRequest =
                new sql.Request(dbPool);

            queryRequest.input(
                'search',
                sql.NVarChar,
                `%${searchTerm}%`
            );

            // Pull descriptions and file links for ALL students
            // matching the keyword search
            const result = await queryRequest.query(`
                SELECT
                    s.SubmissionID,
                    u.UserEmail,
                    s.FileDescription,
                    s.BlobStorageURL,
                    s.UploadedAt
                FROM StudentSubmissions s
                JOIN AppUsers u
                    ON s.StudentObjectID = u.UserObjectID
                WHERE
                    s.FileDescription LIKE @search
                    OR s.OriginalFileName LIKE @search
                ORDER BY
                    s.UploadedAt DESC
            `);

            // Send the JSON metadata list back to your Admin HTML page
            res.json(result.recordset);

        } catch (error) {

            res.status(500).send(
                "Failed to retrieve master asset list."
            );
        }
    }
);