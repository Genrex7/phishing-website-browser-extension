 
document.addEventListener('DOMContentLoaded', function () {
    const apiKey = localStorage.getItem('virustotal_apikey');
    const resultElement = document.getElementById('result');
    const instructionList = document.getElementById('instruction-list');

    if (!apiKey) {
        // Check if the API key input and submit button already exist
        const existingInput = document.getElementById('api-key');
        const existingButton = document.getElementById('submit-api-key');

        if (!existingInput && !existingButton) {
            // Show the instruction list
            instructionList.classList.add('visible');

            // Show the message for entering the API key
            const apiKeyInput = document.createElement('input');
            apiKeyInput.type = 'text';
            apiKeyInput.id = 'api-key';
            apiKeyInput.placeholder = 'Enter your VirusTotal API key';

            const submitButton = document.createElement('button');
            submitButton.id = 'submit-api-key';
            submitButton.innerText = 'Submit';

            submitButton.addEventListener('click', function () {
                const enteredApiKey = apiKeyInput.value.trim();
                if (enteredApiKey) {
                    // Verify the API key before saving it
                    verifyApiKey(enteredApiKey)
                        .then((isValid) => {
                            if (isValid) {
                                localStorage.setItem('virustotal_apikey', enteredApiKey);
                                performVirusTotalAnalysis(enteredApiKey);
                                // Hide the instruction list after getting the API key
                                instructionList.classList.remove('visible');
                                // Remove the input field and submit button after getting the API key
                                apiKeyInput.remove();
                                submitButton.remove();
                            } else {
                                resultElement.innerText = 'Please enter a valid VirusTotal API key.';
                            }
                        })
                        .catch((error) => {
                            console.error(error);
                            resultElement.innerText = 'An error occurred while verifying the API key.';
                        });
                } else {
                    resultElement.innerText = 'Please enter a valid VirusTotal API key.';
                }
            });

            // Add the input field and submit button to the popup
            document.body.appendChild(apiKeyInput);
            document.body.appendChild(submitButton);
        }
    } else {
        // API key already exists, perform VirusTotal analysis directly
        instructionList.classList.remove('visible');
        performVirusTotalAnalysis(apiKey);
    }
    // localStorage.removeItem('virustotal_apikey');
});

function performVirusTotalAnalysis(apiKey) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        var url = tabs[0].url;

        // Convert the URL to a URL identifier or base64 representation
        var encodedUrl = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        var apiUrl = 'https://www.virustotal.com/api/v3/urls/' + encodedUrl;

        const options = {
            method: 'GET',
            headers: {
                accept: 'application/json',
                'x-apikey': apiKey
            }
        };

        fetch(apiUrl, options)
            .then(response => response.json())
            .then(data => {
                var resultElement = document.getElementById('result');

                if (data && data.data && data.data.attributes && data.data.attributes.last_analysis_stats) {
                    if (data.data.attributes.last_analysis_stats.malicious > 0) {
                        resultElement.innerText = 'The website is harmful!';
                    } else {
                        resultElement.innerText = 'The website is clean.';
                    }
                } else {
                    resultElement.innerText = 'Unable to fetch analysis data.';
                }
            })
            .catch(error => {
                console.error(error);
                var resultElement = document.getElementById('result');
                resultElement.innerText = 'Error occurred while fetching data.';
            });
    });
}

// Function to verify the API key (using a simple fetch for demonstration purposes)
function verifyApiKey(apiKey) {
    const apiUrl = 'https://www.virustotal.com/api/v3/info';
    const options = {
        method: 'GET',
        headers: {
            'x-apikey': apiKey
        }
    };

    return fetch(apiUrl, options)
        .then(response => response.json())
        .then(data => data.data && data.data.api_version)
        .catch(error => {
            console.error(error);
            return false;
        });
}

