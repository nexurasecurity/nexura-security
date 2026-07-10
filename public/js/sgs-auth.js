jQuery(document).ready(function($) {
    function handleAuthForm(formId, action) {
        $(formId).on('submit', function(e) {
            e.preventDefault();
            
            var $form = $(this);
            var $btn = $form.find('button[type="submit"]');
            var $btnText = $btn.find('.nexura-btn-text');
            var $loader = $btn.find('.nexura-loader');
            var $msg = $form.find('.nexura-auth-message');

            $btn.prop('disabled', true);
            $loader.show();
            $msg.hide().removeClass('nexura-error nexura-success').text('');

            var data = $form.serialize() + '&action=' + action + '&security=' + NEXURA_auth_ajax.nonce;

            $.post(NEXURA_auth_ajax.ajaxurl, data, function(response) {
                if (response.success) {
                    $msg.addClass('nexura-success').text(response.data.message).fadeIn();
                    if (response.data.redirect) {
                        setTimeout(function() {
                            window.location.href = response.data.redirect;
                        }, 1000);
                    }
                } else {
                    $btn.prop('disabled', false);
                    $loader.hide();
                    $msg.addClass('nexura-error').text(response.data.message || 'An error occurred.').fadeIn();
                }
            }).fail(function() {
                $btn.prop('disabled', false);
                $loader.hide();
                $msg.addClass('nexura-error').text('A server error occurred. Please try again.').fadeIn();
            });
        });
    }

    handleAuthForm('#nexura-login-form', 'NEXURA_ajax_login');
    handleAuthForm('#nexura-register-form', 'NEXURA_ajax_register');
});
