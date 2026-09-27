const { DefaultAzureCredential } = require("@azure/identity");
const { BlobServiceClient } = require("@azure/storage-blob");
const fs = require("fs");
const path = require("path");

// 1. Initialize DefaultAzureCredential
// This automatically picks up your App Service's Managed Identity when deployed to Azure
const credential = new DefaultAzureCredential();

// 2. Configure your Storage Account Connection
const accountName = "YOUR_EASTUS_STORAGE_ACCOUNT_NAME"; // Replace with your exact storage account name
const blobServiceClient = new BlobServiceClient(
    `https://${accountName}.blob.core.windows.net`,
    credential
);

async function uploadImageFile(containerName, localFilePath) {
    try {
        // 3. Get a reference to your target container
        const containerClient = blobServiceClient.getContainerClient(containerName);

        // Optional: Automatically create the container if it doesn't exist yet
        await containerClient.createIfNotExists({ accessType: 'blob' });
        console.log(`Container "${containerName}" verified.`);

        // 4. Prepare the blob destination name
        const blobName = path.basename(localFilePath);
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);

        console.log(`Uploading ${blobName} to Azure Blob Storage...`);

        // 5. Stream the local file data directly up to the cloud
        const fileStream = fs.createReadStream(localFilePath);
        await blockBlobClient.uploadStream(fileStream);

        console.log(`Success! File uploaded safely. URL: ${blockBlobClient.url}`);
    } catch (error) {
        console.error("Error executing upload process:", error.message);
    }
}

// Example usage execution:
// Make sure you have a test file named "avatar.png" in your project directory
const targetContainer = "portfolio-images";
const localFile = path.join(__dirname, "avatar.png");

uploadImageFile(targetContainer, localFile);
