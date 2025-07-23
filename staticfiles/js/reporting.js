/**
 * Reporting Form Enhancement Script
 * Enhances the phishing report form with interactive features
 */

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('reportForm');
    const submitButton = form?.querySelector('button[type="submit"]');
    
    // Form submission enhancement
    if (form && submitButton) {
        form.addEventListener('submit', function(e) {
            // Add loading state
            submitButton.classList.add('submitting');
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Ուղարկվում է...';
            submitButton.disabled = true;
            
            // Basic client-side validation
            const description = form.querySelector('textarea[name="description"]');
            const suspiciousUrl = form.querySelector('input[name="suspicious_url"]');
            const suspiciousEmail = form.querySelector('input[name="suspicious_email"]');
            
            if (description && description.value.trim().length < 10) {
                e.preventDefault();
                showNotification('Նկարագրությունը պետք է պարունակի առնվազն 10 նիշ', 'error');
                resetSubmitButton();
                return;
            }
            
            if ((!suspiciousUrl || !suspiciousUrl.value.trim()) && 
                (!suspiciousEmail || !suspiciousEmail.value.trim())) {
                e.preventDefault();
                showNotification('Խնդրում ենք տրամադրել առնվազն կասկածելի URL-ը կամ էլ. փոստը', 'error');
                resetSubmitButton();
                return;
            }
        });
    }
    
    // Auto-resize textarea
    const textareas = document.querySelectorAll('textarea');
    textareas.forEach(textarea => {
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 200) + 'px';
        });
        
        // Initial resize
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 200) + 'px';
    });
    
    // Character counter for description
    const descriptionField = document.querySelector('textarea[name="description"]');
    if (descriptionField) {
        const counterDiv = document.createElement('div');
        counterDiv.className = 'form-text text-end';
        counterDiv.id = 'description-counter';
        descriptionField.parentNode.appendChild(counterDiv);
        
        function updateCounter() {
            const length = descriptionField.value.length;
            const minLength = 10;
            const maxLength = 1000;
            
            counterDiv.textContent = `${length}/${maxLength} նիշ`;
            
            if (length < minLength) {
                counterDiv.className = 'form-text text-end text-warning';
                counterDiv.textContent += ` (առնվազն ${minLength} նիշ)`;
            } else if (length > maxLength * 0.9) {
                counterDiv.className = 'form-text text-end text-warning';
            } else {
                counterDiv.className = 'form-text text-end text-success';
            }
        }
        
        descriptionField.addEventListener('input', updateCounter);
        updateCounter(); // Initial count
    }
    
    // URL validation
    const urlField = document.querySelector('input[name="suspicious_url"]');
    if (urlField) {
        urlField.addEventListener('blur', function() {
            const url = this.value.trim();
            if (url && !isValidUrl(url)) {
                showFieldError(this, 'Խնդրում ենք մուտքագրել վավեր URL հասցե');
            } else {
                clearFieldError(this);
            }
        });
    }
    
    // Email validation
    const emailField = document.querySelector('input[name="suspicious_email"]');
    if (emailField) {
        emailField.addEventListener('blur', function() {
            const email = this.value.trim();
            if (email && !isValidEmail(email)) {
                showFieldError(this, 'Խնդրում ենք մուտքագրել վավեր էլ. փոստի հասցե');
            } else {
                clearFieldError(this);
            }
        });
    }
    
    // Category-based form customization
    const categoryField = document.querySelector('select[name="category"]');
    if (categoryField) {
        categoryField.addEventListener('change', function() {
            customizeFormByCategory(this.value);
        });
        
        // Initial customization
        customizeFormByCategory(categoryField.value);
    }
    
    // Auto-save draft (localStorage)
    if (form) {
        const draftKey = 'reporting_form_draft';
        
        // Load draft
        loadDraft();
        
        // Save draft on input
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('input', saveDraft);
        });
        
        // Clear draft on successful submission
        form.addEventListener('submit', function() {
            localStorage.removeItem(draftKey);
        });
        
        function saveDraft() {
            const formData = new FormData(form);
            const draftData = {};
            for (let [key, value] of formData.entries()) {
                if (key !== 'csrfmiddlewaretoken') {
                    draftData[key] = value;
                }
            }
            localStorage.setItem(draftKey, JSON.stringify(draftData));
        }
        
        function loadDraft() {
            const draft = localStorage.getItem(draftKey);
            if (draft) {
                try {
                    const draftData = JSON.parse(draft);
                    Object.keys(draftData).forEach(key => {
                        const field = form.querySelector(`[name="${key}"]`);
                        if (field) {
                            if (field.type === 'checkbox') {
                                field.checked = draftData[key] === 'on';
                            } else {
                                field.value = draftData[key];
                            }
                        }
                    });
                    
                    // Show draft notification
                    if (Object.keys(draftData).length > 0) {
                        showNotification('Բեռնվել է նախկինում պահպանված կեսատվով տվյալը', 'info');
                    }
                } catch (e) {
                    localStorage.removeItem(draftKey);
                }
            }
        }
    }
    
    // Helper functions
    function resetSubmitButton() {
        if (submitButton) {
            submitButton.classList.remove('submitting');
            submitButton.innerHTML = '<i class="fas fa-paper-plane me-2"></i>Ուղարկել զեկուցումը';
            submitButton.disabled = false;
        }
    }
    
    function showNotification(message, type = 'info') {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert ${type === 'error' ? 'alert-error' : 'alert-custom'} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Փակել"></button>
        `;
        
        const container = document.querySelector('.container');
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, 5000);
        }
    }
    
    function showFieldError(field, message) {
        clearFieldError(field);
        
        field.classList.add('is-invalid');
        const errorDiv = document.createElement('div');
        errorDiv.className = 'invalid-feedback';
        errorDiv.textContent = message;
        field.parentNode.appendChild(errorDiv);
    }
    
    function clearFieldError(field) {
        field.classList.remove('is-invalid');
        const errorDiv = field.parentNode.querySelector('.invalid-feedback');
        if (errorDiv) {
            errorDiv.remove();
        }
    }
    
    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    function customizeFormByCategory(category) {
        const formCard = document.querySelector('.reporting-form-card');
        if (formCard) {
            // Remove existing category classes
            formCard.classList.remove(
                'category-banking', 'category-social_media', 'category-sms', 
                'category-email', 'category-cryptocurrency', 'category-online_shopping', 
                'category-government', 'category-other'
            );
            
            // Add new category class
            if (category) {
                formCard.classList.add(`category-${category}`);
            }
        }
        
        // Show/hide relevant fields based on category
        const urlField = document.querySelector('input[name="suspicious_url"]').closest('.mb-3');
        const emailField = document.querySelector('input[name="suspicious_email"]').closest('.mb-3');
        
        if (category === 'sms') {
            // For SMS phishing, URL is more important than email
            urlField.classList.add('col-md-8');
            emailField.classList.add('col-md-4');
        } else if (category === 'email') {
            // For email phishing, email is more important than URL
            urlField.classList.add('col-md-4');
            emailField.classList.add('col-md-8');
        } else {
            // Default layout
            urlField.classList.remove('col-md-4', 'col-md-8');
            emailField.classList.remove('col-md-4', 'col-md-8');
        }
    }
});

// Contact card hover effects
document.addEventListener('DOMContentLoaded', function() {
    const contactCards = document.querySelectorAll('.contact-card');
    
    contactCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(-2px)';
        });
    });
});

// Smooth scroll for internal links
document.addEventListener('DOMContentLoaded', function() {
    const links = document.querySelectorAll('a[href^="#"]');
    
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});
