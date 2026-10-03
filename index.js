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
const upload = multer({ storage: multer.memoryStorage() });

// ==========================================
// 1. STATE & SECURITY SESSION CONFIGURATION
// ==========================================

const sessionSecret =
    process.env.SESSION_SECRET || 'local-development-session-secret';

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        // App Service/Front Door uses HTTPS in production.
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax'
    }
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ==========================================
// 2. AZURE INFRASTRUCTURE CONFIGURATION
// ==========================================

// Blob Storage continues to use the App Service managed identity.
// SQL Database uses standard SQL username/password authentication.
const azureCredential = new DefaultAzureCredential();

const storageAccountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
const sqlServerName = process.env.AZURE_SQL_SERVER_NAME;
const sqlDatabaseName = process.env.AZURE_DATABASE_NAME;
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;

if (!sqlServerName) {
    throw new Error(
        'Missing required environment variable: AZURE_SQL_SERVER_NAME'
    );
}

if (!sqlDatabaseName) {
    throw new Error(
        'Missing required environment variable: AZURE_DATABASE_NAME'
    );
}

if (!dbUser) {
    throw new Error(
        'Missing required environment variable: DB_USER'
    );
}

if (!dbPassword) {
    throw new Error(
        'Missing required environment variable: DB_PASSWORD'
    );
}

if (!storageAccountName) {
    console.warn(
        'WARNING: AZURE_STORAGE_ACCOUNT_NAME is not configured. ' +
        'Blob upload functionality will not work until it is set.'
    );
}

// Only create the Blob client when the storage account name exists.
// This keeps SQL/authentication startup independent of Blob configuration.
const blobServiceClient = storageAccountName
    ? new BlobServiceClient(
        `https://${storageAccountName}.blob.core.windows.net`,
        azureCredential
    )
    : null;

// ==========================================
// 3. AZURE SQL CONNECTION
// ==========================================

let dbPool;

async function initializeDatabaseConnection() {

    console.log(
        `Connecting to Azure SQL Server "${sqlServerName}" ` +
        `using SQL Authentication...`
    );

    const sqlConfig = {
        server: `${sqlServerName}.database.windows.net`,
        database: sqlDatabaseName,
        user: dbUser,
        password: dbPassword,

        authentication: {
            type: 'default'
        },

        options: {
            encrypt: true,
            trustServerCertificate: false
        }
    };

    try {

        dbPool = await sql.connect(sqlConfig);

        console.log(
            'SUCCESS: Connected to Azure SQL Database using SQL Authentication!'
        );

        return dbPool;

    } catch (error) {

        console.error(
            'Database connection failure:',
            error.message
        );

        throw error;
    }
}

// ==========================================
// 4. ENTRA ID WEB LOGIN CONFIGURATION
// ==========================================

const entraClientId = process.env.Entra_ClientId;
const entraClientSecret = process.env.Entra_ClientSecret;

const entraTenantId =
    process.env.Entra_TenantId ||
    process.env.ENTRA_TENANT_ID ||
    'common';

const redirectUri =
    process.env.ENTRA_REDIRECT_URI ||
    `https://${process.env.WEBSITE_HOSTNAME || 'localhost:3000'}/auth/callback`;

if (!entraClientId) {

    console.warn(
        'WARNING: Entra_ClientId is not configured. ' +
        'Web login will not work until Entra ID settings are supplied.'
    );
}

if (!entraClientSecret) {

    console.warn(
        'WARNING: Entra_ClientSecret is not configured. ' +
        'Web login will not work until Entra ID settings are supplied.'
    );
}

const msalConfig = {

    auth: {

        clientId: entraClientId,

        authority:
            `https://login.microsoftonline.com/${entraTenantId}`,

        clientSecret: entraClientSecret
    }
};

const cca =
    entraClientId && entraClientSecret
        ? new msal.ConfidentialClientApplication(msalConfig)
        : null;

// ==========================================
// 5. BASIC HEALTH CHECK
// ==========================================

app.get('/health', (req, res) => {

    res.status(200).json({

        status: 'ok',

        database:
            dbPool
                ? 'connected'
                : 'not-connected'
    });
});

// ==========================================
// 6. SECURITY GATE MIDDLEWARE (RBAC)
// ==========================================

async function authorizeUserRole(req, res, next) {

    try {

        // Authenticated Gate Check
        if (!req.session.isAuthenticated) {

            return res.redirect('/login.html');
        }

        const userOID =
            req.session.userObjectID;

        const userEmail =
            req.session.userEmail;

        if (!dbPool) {

            return res.status(503).send(
                'Database connection is not ready. Please try again shortly.'
            );
        }

        const queryRequest =
            new sql.Request(dbPool);

        queryRequest.input(
            'oid',
            sql.VarChar,
            userOID
        );

        const dbResult =
            await queryRequest.query(
                "SELECT UserRole FROM AppUsers WHERE UserObjectID = @oid"
            );

        // If the user doesn't exist in your SQL database yet,
        // automatically register them as a default 'Student'
        if (dbResult.recordset.length === 0) {

            const insertRequest =
                new sql.Request(dbPool);

            insertRequest.input(
                'oid',
                sql.VarChar,
                userOID
            );

            insertRequest.input(
                'email',
                sql.VarChar,
                userEmail
            );

            await insertRequest.query(
                "INSERT INTO AppUsers (UserObjectID, UserEmail, UserRole) VALUES (@oid, @email, 'Student')"
            );

            req.userRole = 'Student';

        } else {

            // Extract the user's role from the SQL database
            req.userRole =
                dbResult.recordset[0].UserRole;
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
// 7. ROUTING & CONTROLLERS
// ==========================================

// --- THE LOGIN ROUTE INTERCEPTOR ---

app.get('/auth/login', async (req, res) => {

    if (!cca) {

        return res.status(500).send(
            'Entra ID login is not configured on this App Service.'
        );
    }

    const authCodeUrlParameters = {

        scopes: [
            "user.read"
        ],

        // Send the user to the configured callback URL
        redirectUri: redirectUri
    };

    try {

        const response =
            await cca.getAuthCodeUrl(
                authCodeUrlParameters
            );

        res.redirect(response);

    } catch (error) {

        console.error(
            "Entra login URL generation error:",
            error.message
        );

        res.status(500).send(
            "Error generating Entra ID challenge payload."
        );
    }
});

// --- THE ENTRA ID LANDING ZONE ---

app.get('/auth/callback', async (req, res) => {

    if (!cca) {

        return res.status(500).send(
            'Entra ID login is not configured on this App Service.'
        );
    }

    if (!req.query.code) {

        return res.status(400).send(
            'Missing authorization code from Entra ID.'
        );
    }

    const tokenRequest = {

        code: req.query.code,

        scopes: [
            "user.read"
        ],

        redirectUri: redirectUri
    };

    try {

        const authResult =
            await cca.acquireTokenByCode(
                tokenRequest
            );

        const decodedToken =
            jwt.decode(
                authResult.idToken
            );

        // Commit core identification variables directly into the session
        req.session.isAuthenticated = true;

        req.session.userObjectID =
            decodedToken.oid;

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

            if (!blobServiceClient) {

                return res.status(503).send(
                    'Blob Storage is not configured on this App Service.'
                );
            }

            if (!dbPool) {

                return res.status(503).send(
                    'Database connection is not ready. Please try again shortly.'
                );
            }

            // Double-check security bounds
            if (
                req.userRole !== 'Student' &&
                req.userRole !== 'Admin'
            ) {

                return res.status(403).send(
                    "Forbidden: Only portfolio holders can upload files."
                );
            }

            const fileDescription =
                req.body.description;

            const filePayload =
                req.file;

            const studentOID =
                req.session.userObjectID;

            if (!filePayload || !fileDescription) {

                return res.status(400).send(
                    "Required portfolio metadata or payload structural assets are missing."
                );
            }

            // Phase 1:
            // Stream the raw payload privately to Blob Storage
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

            const savedBlobURL =
                blockBlobClient.url;

            // Phase 2:
            // Log file metadata inside Azure SQL
            console.log(
                "Syncing blob text metadata tracking rows into Azure SQL..."
            );

            const queryRequest =
                new sql.Request(dbPool);

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

            if (!dbPool) {

                return res.status(503).send(
                    'Database connection is not ready. Please try again shortly.'
                );
            }

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
            const result =
                await queryRequest.query(`
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

            // Send the JSON metadata list back to Admin HTML page
            res.json(
                result.recordset
            );

        } catch (error) {

            console.error(
                "Admin search error:",
                error.message
            );

            res.status(500).send(
                "Failed to retrieve master asset list."
            );
        }
    }
);

// ==========================================
// 8. APPLICATION STARTUP
// ==========================================

const port =
    Number(process.env.PORT) || 3000;

async function startServer() {

    try {

        // Do not start accepting HTTP traffic until
        // the database connection is established.
        await initializeDatabaseConnection();

        app.listen(
            port,
            () => {

                console.log(
                    `CCIQ server listening on port ${port}`
                );
            }
        );

    } catch (error) {

        console.error(
            'FATAL: Application startup failed.',
            error.message
        );

        process.exit(1);
    }
}

startServer();