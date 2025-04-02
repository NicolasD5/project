document.addEventListener('DOMContentLoaded', function () {
    const forms = document.querySelectorAll('form'); // Select all forms on the page so it is applied to all user input fields

    forms.forEach(form => {
        form.addEventListener('submit', function (event) {
            const inputs = form.querySelectorAll('input[type="text"], input[type="password"], input[type="tel"], input[type="email"], textarea'); 
            //Defines the fields that the sanitise function will apply

            inputs.forEach(input => {
                input.value = sanitise(input.value);
            });
        });
    });

    function sanitise(value) {
        // Replace special characters with their HTML entity equivalents to ensure that there is no script injected in the input fields
        return value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }
});