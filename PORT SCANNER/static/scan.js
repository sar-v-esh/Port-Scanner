document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('scan-form');
    const resultsContainer = document.getElementById('results-container');
    const scanResults = document.getElementById('scan-results');
    const scanUpdates = document.getElementById('scan-updates');
    const scanButton = document.getElementById('scan-button'); // Add a reference to the scan button
    let source;

    form.addEventListener('submit', function (event) {
        event.preventDefault();
        scanButton.innerText = 'Scanning'; // Update the button text

        if (source) {
            source.close();
        }

        const formData = new FormData(form);

        fetch('/scan', {
            method: 'POST',
            body: formData,
        })
        .then(response => {
            if (response.status === 200) {
                source = new EventSource('/scan-updates');
                source.onmessage = function (event) {
                    const update = JSON.parse(event.data);
                    scanUpdates.textContent += `${update}\n`;
                };
            }
            return response.json();
        })
        .then(data => {
            displayResults(data);
            scanButton.innerText = 'Scan Ports'; // Restore the button text
        })
        .catch(error => {
            console.error('Error:', error);
            scanButton.innerText = 'Scan Ports'; // Restore the button text in case of an error
        });
    });

    function displayResults(results) {
        scanResults.textContent = '';

        results.forEach(result => {
            scanResults.textContent += `Results for ${result.target}:\n`;
            scanResults.textContent += 'Open ports:\n';

            result.open_ports.forEach(portInfo => {
                scanResults.textContent += `Port ${portInfo[0]} (${portInfo[1].name || 'Unknown'}) is open. Version: ${portInfo[1].version || 'Unknown'} (${portInfo[1].product || 'Unknown'})\n`;
            });

            scanResults.textContent += 'Geolocation Information:\n';
            scanResults.textContent += `IP Address: ${result.geolocation.ip_address || 'Unknown'}\n`;
            scanResults.textContent += `Location: ${result.geolocation.location || 'Unknown'}\n\n`;
        }
        );
    }
});
