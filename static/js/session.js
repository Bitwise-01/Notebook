'use strict';

let mouseMoved = false;
let isLoggedOut = false;
let updatingSession = false;
let lastUpdated = new Date();
const sessionUpdateDelay = 5 * 1000; // 5 Seconds
const sessionCheckDelay = (60 * 2 + 5) * 1000; // (Session's TTL + a few seconds) 2 minutes + 5 seconds

$(document).ready(() => {
    $(document).mousemove(() => {
        mouseMoved = true;
    });

    setInterval(sessionCheck, sessionCheckDelay);
    setInterval(sessionUpdate, sessionUpdateDelay);
});

function sessionCheck() {
    if (isLoggedOut || updatingSession) {
        return;
    }

    if (new Date().getTime() - lastUpdated.getTime() <= sessionUpdateDelay) {
        return;
    }

    updatingSession = true;

    $.ajax({
        type: 'POST',
        url: '/session_check'
    }).done(function(resp) {
        let respCode = resp['resp'];

        mouseMoved = false;
        updatingSession = false;
        lastUpdated = new Date();

        if (respCode != 0) {
            isLoggedOut = true;
            window.location.href = '/';
        }
    });
}

function sessionUpdate() {
    if (!mouseMoved || updatingSession) {
        return;
    }

    sessionCheck();
}
