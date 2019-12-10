'use strict';

let isPrompt = false;
const userId = $('#user-id').text();
const username = $('#username').text();

function updateAccess() {
    let accessId = $('#new-access option:selected').val();

    $.ajax({
        type: 'POST',
        url: '/update_access',
        data: { user_id: userId, access_id: accessId },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(function(resp) {
        let respMsg = resp['resp'];

        if (respMsg == 'success-msg') {
            location.reload();
        }
    });
}

function logout() {
    $.ajax({
        type: 'POST',
        url: '/logout_user',
        data: { user_id: userId },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(function(resp) {
        let respMsg = resp['resp'];
        let respDisplay = $('#resp');

        if (respMsg == 'success') {
            respDisplay.attr({ class: 'success' });
            respDisplay.text(`Successfully Logged out ${username}`);
        } else {
            respDisplay.text('');
        }
    });
}

function deleteUser(code) {
    let overlay = $('#overlay');
    let topicId = $('#topic-id').text();

    overlay.css({ display: isPrompt ? 'none' : 'block' });
    $('html').css({ overflow: isPrompt ? 'auto' : 'hidden' });
    $('body').css({ overflow: isPrompt ? 'auto' : 'hidden' });
    isPrompt = !isPrompt;

    if (code == 1) {
        $.ajax({
            type: 'POST',
            url: '/delete_user',
            data: { user_id: userId },
            beforeSend: function(request) {
                request.setRequestHeader('X-CSRFToken', CSRFToken);
            }
        }).done(function(resp) {
            let respMsg = resp['resp'];

            if (respMsg == 'success') {
                window.location.href = '/admin';
            }
        });
    }
}
