document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const criteria = {
        length: document.getElementById('length'),
        uppercase: document.getElementById('uppercase'),
        lowercase: document.getElementById('lowercase'),
        number: document.getElementById('number'),
        special: document.getElementById('special'),
        spaces: document.getElementById('spaces')
    };

    passwordInput.addEventListener('input', function() {
        const password = this.value;

        //Check each criteria to ensure password is secure
        checkAndUpdateCriteria(criteria.length, password.length >= 8);
        checkAndUpdateCriteria(criteria.uppercase, /[A-Z]/.test(password));
        checkAndUpdateCriteria(criteria.lowercase, /[a-z]/.test(password));
        checkAndUpdateCriteria(criteria.number, /[0-9]/.test(password));
        checkAndUpdateCriteria(criteria.special, /[@$!%*?&]/.test(password));
        checkAndUpdateCriteria(criteria.spaces, !/[ ]/.test(password));
    });

    function checkAndUpdateCriteria(element, isValid) {
        if (isValid) {
            if (!element.classList.contains('valid')) {
                element.classList.remove('invalid');
                element.classList.add('valid');
                setTimeout(() => {
                    element.style.opacity = '0'; //Fade out the element
                    setTimeout(() => {
                        element.style.display = 'none'; //Hide the element after fading out
                    }, 500); //Wait for the fade-out transition to complete
                }, 500); //0.5-second delay before starting the fade-out
            }
        } else {
            element.style.display = 'block'; //Ensure the element is visible if invalid
            element.style.opacity = '1'; //Reset opacity to make it visible
            element.classList.remove('valid');
            element.classList.add('invalid');
        }
    }
});
