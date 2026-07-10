(function($) {
    'use strict';

    if (typeof NEXURA_session === 'undefined') {
        return;
    }

    var timeout = parseInt(NEXURA_session.timeout_ms);
    var warningTime = 60000; // 1 minute warning
    var timer;
    var isWarningShown = false;

    function resetTimer() {
        clearTimeout(timer);
        if (isWarningShown) {
            $('.nexura-session-warning').remove();
            isWarningShown = false;
        }

        timer = setTimeout(showWarning, timeout - warningTime);
    }

    function showWarning() {
        isWarningShown = true;
        var warningHtml = '<div class="nexura-session-warning" style="position:fixed;top:20px;right:20px;background:#f59e0b;color:#fff;padding:15px 20px;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.15);z-index:999999;font-family:sans-serif;font-weight:600;">' + NEXURA_session.warning_msg + '</div>';
        $('body').append(warningHtml);

        timer = setTimeout(logoutUser, warningTime);
    }

    function logoutUser() {
        $.ajax({
            url: NEXURA_session.ajax_url,
            method: 'POST',
            data: {
                action: 'NEXURA_idle_logout',
                nonce: NEXURA_session.nonce
            },
            success: function(response) {
                if (response.success && response.data.redirect) {
                    window.location.href = response.data.redirect;
                }
            }
        });
    }

    // Bind events to reset timer
    $(document).on('mousemove keydown scroll click', function() {
        resetTimer();
    });

    // Start timer on load
    resetTimer();

})(jQuery);
