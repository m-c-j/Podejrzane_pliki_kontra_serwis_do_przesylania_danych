document.addEventListener('DOMContentLoaded', function() {

    // 1. Lista dozwolonych rozszerzeń (musi być zgodna z Pythonem)
    const allowedExtensions = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'zip', 'rar', '7z'];

    // 2. Pobieramy elementy ze strony
    const fileInput = document.getElementById('fileInput');
    const errorDiv = document.getElementById('fileError');
    const submitBtn = document.getElementById('submitBtn');

    // Sprawdzamy czy elementy istnieją (na wypadek gdybyś użył skryptu na innej stronie)
    if (fileInput && errorDiv && submitBtn) {

        // 3. Nasłuchujemy zmiany
        fileInput.addEventListener('change', function() {
            const filePath = this.value;

            if (!filePath) return;

            const extension = filePath.split('.').pop().toLowerCase();

            if (allowedExtensions.includes(extension)) {
                // JEST OK
                errorDiv.style.display = 'none';
                submitBtn.disabled = false;
                submitBtn.classList.remove('btn-secondary');
                submitBtn.classList.add('btn-success');
                submitBtn.innerText = "Wyślij plik na serwer";
            } else {
                // JEST BŁĄD
                errorDiv.style.display = 'block';
                errorDiv.innerText = `❌ Niepoprawny format pliku (.${extension})! Wybierz inny.`;

                submitBtn.disabled = true;
                submitBtn.classList.remove('btn-success');
                submitBtn.classList.add('btn-secondary');
                submitBtn.innerText = "⛔ Zły format pliku";
            }
        });
    }
});