(function($) {
    'use strict';

    if (typeof NEXURA_session === 'undefined') {
        return;
    }

    var timeout = parseInt(NEXURA_session.timeout_ms, 10);
    var warningTime = 60000; // 1 minute warning
    if (!timeout || timeout <= warningTime) {
        return;
    }

    var timer;
    var isWarningShown = false;

    function isScanActive() {
        // Never log out the admin while a malware/FIM/reinfection scan is actively running
        var stopBtn = document.getElementById('nexura-stop-scan-btn');
        if (stopBtn && stopBtn.offsetParent !== null) {
            return true;
        }
        return false;
    }

    function resetTimer() {
        clearTimeout(timer);
        if (isWarningShown) {
            $('.nexura-session-warning').remove();
            isWarningShown = false;
        }

        timer = setTimeout(showWarning, timeout - warningTime);
    }

    function showWarning() {
        if (isScanActive()) {
            resetTimer();
            return;
        }
        isWarningShown = true;
        var warningHtml = '<div class="nexura-session-warning" style="position:fixed;top:20px;right:20px;background:#f59e0b;color:#fff;padding:15px 20px;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.15);z-index:999999;font-family:sans-serif;font-weight:600;"></div>';
        $('body').append($(warningHtml).text(NEXURA_session.warning_msg));

        timer = setTimeout(logoutUser, warningTime);
    }

    function logoutUser() {
        if (isScanActive()) {
            resetTimer();
            return;
        }
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

    // Bind user activity + background AJAX/REST scan activity to reset timer
    $(document).on('mousemove keydown scroll click ajaxSend', function() {
        resetTimer();
    });

    if (typeof window.fetch === 'function') {
        var origFetch = window.fetch;
        window.fetch = function() {
            resetTimer();
            return origFetch.apply(this, arguments);
        };
    }

    // Start timer on load
    resetTimer();

})(jQuery);
