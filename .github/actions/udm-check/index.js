const core = require('@actions/core');
const fs = require('fs');
const path = require('path');

async function run() {
  try {
    // Set the base directory to the root of the repository
    const baseDir = process.env.GITHUB_WORKSPACE;
    
    let foundIssues = false;

    // Recursively find all .yara and .yar files in the repository
    function findFiles(dir) {
      const files = fs.readdirSync(dir);

      files.forEach(file => {
        const filePath = path.join(dir, file);
        const stat = fs.lstatSync(filePath);

        if (stat.isDirectory()) {
          findFiles(filePath);
        } else if (file.endsWith('.yara') || file.endsWith('.yar')) {
          checkFile(filePath);
        }
      });
    }

    // Function to check the file for UDM field conditions
    function checkFile(file) {
      const content = fs.readFileSync(file, 'utf8');

      // Regex to find all UDM fields with '!='
      const udmFields = content.match(/\$e\.[a-zA-Z0-9_.]+ != "[^"]+"/g);

      if (udmFields) {
        udmFields.forEach(field => {
          const baseField = field.split('!=')[0].trim();
          const expectedCheck = `${baseField} != ""`;

          if (!content.includes(expectedCheck)) {
            foundIssues = true;
            core.error(`In file ${file}, found UDM field '${field}' without a corresponding check for '${expectedCheck}'.`);
          }
        });
      }
    }

    // Start scanning from the base directory
    findFiles(baseDir);

    if (foundIssues) {
      core.setFailed("UDM field checks failed.");
    } else {
      core.setOutput('result', 'success');
      core.info("All UDM field checks passed.");
    }
  } catch (error) {
    core.setFailed(`Action failed with error: ${error.message}`);
  }
}

run();
