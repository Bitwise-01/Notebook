'use strict';

let isLoggedOut = false;
const sessionCheckDelay = ((60 * 2) + 5) * 1000; // (Session's TTL + a few seconds) 2 minutes + 5 seconds

$(document).ready(() => {
    setInterval(sessionCheck, sessionCheckDelay);
});

function sessionCheck() {
    if (isLoggedOut) {
        return;
    }

    $.ajax({
        type: 'POST',
        url: '/session_check'
    }).done(function(resp) {
        let respCode = resp['resp'];

        if (respCode != 0) {
            isLoggedOut = true;
            window.location.href = '/';
        } 
    });
}