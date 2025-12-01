document.addEventListener('DOMContentLoaded', function() {
    const downloadForms = document.querySelectorAll('table form');

    // Funkcja do wyświetlania dymków powiadomień
    function showToast(message, type = 'info', autoHide = true) {
        // Usuń stary toast
        const oldAlert = document.getElementById('download-toast');
        if(oldAlert) oldAlert.remove();

        const alertDiv = document.createElement('div');
        alertDiv.id = 'download-toast';

        // Kolory w zależności od typu
        let alertClass = 'alert-info';
        let icon = 'ℹ️';
        if (type === 'success') { alertClass = 'alert-success'; icon = '✅'; }
        if (type === 'danger') { alertClass = 'alert-danger'; icon = '⛔'; }
        if (type === 'warning') { alertClass = 'alert-warning'; icon = '⏳'; }

        alertDiv.className = `alert ${alertClass} alert-dismissible fade show shadow-lg`;
        alertDiv.role = 'alert';

        // Style CSS (w kodzie JS)
        Object.assign(alertDiv.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            zIndex: '9999',
            minWidth: '300px',
            maxWidth: '450px'
        });

        alertDiv.innerHTML = `
            <div class="d-flex align-items-center">
                <span class="fs-4 me-2">${icon}</span>
                <div>${message}</div>
            </div>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;

        document.body.appendChild(alertDiv);

        if (autoHide) {
            setTimeout(() => { if(alertDiv) alertDiv.remove(); }, 6000);
        }
    }

    if (downloadForms.length > 0) {
        downloadForms.forEach(form => {
            form.addEventListener('submit', function(e) {

                // Sprawdzamy czy suwak jest zaznaczony
                const safeSwitch = form.querySelector('input[name="safe"]');
                const isSafeMode = safeSwitch ? safeSwitch.checked : false;

                // Jeśli skanowanie wyłączone -> pobieraj normalnie (nic nie rób, niech przeglądarka działa)
                if (!isSafeMode) {
                    showToast('<strong>Rozpoczęto pobieranie...</strong><br><small>Bez skanowania.</small>', 'info');
                    return;
                }

                // JEŚLI SKANOWANIE WŁĄCZONE -> Przejmujemy kontrolę!
                e.preventDefault(); // ZATRZYMUJEMY standardowe wysyłanie formularza

                // Pobieramy nazwę pliku z action URL formularza
                // URL wygląda np. tak: /uploads/plik.txt
                const actionUrl = new URL(form.action, window.location.origin);
                const filename = actionUrl.pathname.split('/').pop();

                showToast('<strong>Skanowanie pliku...</strong><br><small>Proszę czekać, łączę z VirusTotal...</small>', 'warning', false);

                // Pytamy Pythona o status (AJAX)
                fetch(`/api/check_file/${filename}`)
                    .then(response => response.json())
                    .then(data => {

                        if (data.status === 'SAFE') {
                            showToast(`<strong>${data.message}</strong><br>Pobieranie rozpoczęte.`, 'success');
                            // Wymuszamy pobranie pliku (przekierowanie na stary link)
                            window.location.href = form.action;
                        }
                        else if (data.status === 'DANGER' || data.status === 'ERROR') {
                            showToast(`<strong>BLOKADA:</strong> ${data.message}`, 'danger', false);
                            // Nie pobieramy pliku!
                        }
                        else if (data.status === 'QUEUED') {
                            showToast(`<strong>Trwa analiza:</strong> ${data.message}<br>Spróbuj za 2 minuty.`, 'warning', false);
                        }
                        else if (data.status === 'UNKNOWN' || data.status === 'TOO_LARGE') {
                            // W tych przypadkach musimy przenieść użytkownika na stronę potwierdzenia
                            // Po prostu puszczamy formularz "ręcznie" ale z parametrem safe=on
                            window.location.href = `${form.action}?safe=on`;
                        }

                    })
                    .catch(error => {
                        showToast('Wystąpił błąd połączenia z serwerem.', 'danger');
                        console.error('Error:', error);
                    });
            });
        });
    }
});