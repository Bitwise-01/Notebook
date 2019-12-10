'use strict';

let isPrompt = false;

function changeUsername() {
    let display = $('#usr-resp');
    let username = $('#username');

    if (!username.val().length) {
        return;
    }

    $.ajax({
        type: 'POST',
        url: '/updateusername',
        data: { username: username.val() },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(function(resp) {
        let msg = resp['msg'];
        let code = resp['resp_code'];

        display.text(msg);
        display.css({ color: code == 0 ? '#28a745' : '#dc3545' });

        if (code == 0) {
            username.attr('placeholder', clean(username.val()));
            username.val('');
        }
    });
}

function changePassword() {
    let display = $('#pwd-resp');
    let oldPassword = $('#old-pwd');
    let newPassword = $('#new-pwd');
    let confirmPassword = $('#conf');

    if (!(oldPassword.val().length && newPassword.val().length && confirmPassword.val().length)) {
        return;
    }

    display.text('');

    $.ajax({
        type: 'POST',
        url: '/updatepassword',
        data: { old: oldPassword.val(), new: newPassword.val(), conf: confirmPassword.val() },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(function(resp) {
        let msg = resp['msg'];
        let code = resp['resp_code'];

        display.text(msg);
        display.css({ color: code == 0 ? '#28a745' : '#dc3545' });

        if (code == 0) {
            oldPassword.val('');
            newPassword.val('');
            confirmPassword.val('');
        }
    });
}

function deleteAccount(code) {
    let overlay = $('#overlay');

    overlay.css({ display: isPrompt ? 'none' : 'block' });
    $('html').css({ overflow: isPrompt ? 'auto' : 'hidden' });
    $('body').css({ overflow: isPrompt ? 'auto' : 'hidden' });
    isPrompt = !isPrompt;

    if (code == 1) {
        $.ajax({
            type: 'POST',
            url: '/delete_account',
            beforeSend: function(request) {
                request.setRequestHeader('X-CSRFToken', CSRFToken);
            }
        }).done(function(resp) {
            window.location.href = '/';
        });
    }
}
