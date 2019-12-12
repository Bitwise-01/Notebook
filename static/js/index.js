'use strict';

$(document).ready(() => {
    $('#login-form').submit(e => {
        e.preventDefault();
        login();
    });
});

function login() {
    let username = $('#username').val();
    let password = $('#password').val();
    let timestamp = new Date().getTime();

    $.ajax({
        type: 'POST',
        url: '/login',
        data: { username: username, password: password, timestamp: timestamp },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', $('#csrf_token').val());
        }
    })
        .done(resp => {
            let isAuthen = resp['is_authenticated'];
            let msg = resp['msg'];

            if (!isAuthen) {
                let Output = $('<span>', { id: 'msg', class: 'message error' }).append(msg);
                $('#msg').replaceWith(Output);
            } else {
                window.location.href = '/';
            }
        })
        .fail(() => {
            window.location.href = '/';
        });
}
