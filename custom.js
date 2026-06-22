/*
 * Example code for using custom hooks in friTap. 
 * To ensure friTap prints content, include a "custom" field in your message payload. 
 * The value of this "custom" field will be displayed by friTap.
 */

// Iterate over all loaded modules
Process.enumerateModules().forEach(module => {
    // Enumerate exports for each module
    module.enumerateExports().forEach(exp => {
        // Check if the export name contains "ssl" or "tls" || exp.name.toLowerCase().includes("tls")
        if (exp.name.toLowerCase().includes("ssl") ) {
            // Send the result to Python
            send({
                custom: `Found export: ${exp.name} in module: ${module.name} at address: ${exp.address}`
            });
        }
    });
});
