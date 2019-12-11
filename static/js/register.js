'use strict';

let MIN_PASSWORD_LENGTH = null;
let MAX_PASSWORD_LENGTH = null;

$(document).ready(() => {
    MIN_PASSWORD_LENGTH = $('#min-password-length').text();
    MAX_PASSWORD_LENGTH = $('#max-password-length').text();

    testUserInput();
    $('#username').on('change input', testUserInput);
    $('#password').on('change input', testUserInput);
    $('#confirm').on('change input', testUserInput);
});

function testUserInput() {
    let username = $('#username').val();
    let password = $('#password').val();
    let confirmPassword = $('#confirm').val();

    let tests = [
        passwordContainsUsernameTest(username, password),
        passwordMinLengthTest(password),
        passwordMaxLengthTest(password),
        passwordContainsSpaceTest(password),
        passwordStartsEndsWithSpaceTest(password),
        passwordEndsWithNumberTest(password),
        passwordsMatchTest(password, confirmPassword)
    ];

    let msg;
    let status;
    let statusList = $('<ul>', { id: 'status' });

    tests.forEach(test => {
        msg = test.msg;
        status = test.status;
        statusList.append($('<li>', { class: status }).append(msg));
    });

    $('#status').replaceWith(statusList);
}

function passwordContainsUsernameTest(username, password) {
    let _username = [];

    for (let s of username) {
        if (s.match(/[a-zA-Z]/i)) {
            _username.push(s);
        }
    }

    _username = _username.join('').toLowerCase();

    return {
        msg: 'Password must not contain your username',
        status: password.toLowerCase().includes(_username) ? 'error' : 'success'
    };
}

function passwordMinLengthTest(password) {
    return {
        msg: 'Password must be at least ' + MIN_PASSWORD_LENGTH + ' characters long',
        status: password.length < MIN_PASSWORD_LENGTH ? 'error' : 'success'
    };
}

function passwordMaxLengthTest(password) {
    return {
        msg: 'Password must not be longer than ' + MAX_PASSWORD_LENGTH + ' characters',
        status: password.length > MAX_PASSWORD_LENGTH ? 'error' : 'success'
    };
}

function passwordContainsSpaceTest(password) {
    return {
        msg: 'Password must contain at least 1 space character',
        status: !password.match(/\s/) ? 'error' : 'success'
    };
}

function passwordStartsEndsWithSpaceTest(password) {
    return {
        msg: 'Password must not start or end with a space character',
        status: password.match(/(^\s|\s$)/) ? 'error' : 'success'
    };
}

function passwordEndsWithNumberTest(password) {
    return {
        msg: 'Password must not end with a number',
        status: password.match(/\d$/) ? 'error' : 'success'
    };
}

function passwordsMatchTest(password, confirmPassword) {
    return {
        msg: 'Passwords match',
        status: password !== confirmPassword ? 'error' : 'success'
    };
}
