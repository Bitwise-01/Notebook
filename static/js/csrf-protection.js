'use strict';

let CSRFToken = null;

$(document).ready(() => {
    CSRFToken = $('#csrf_token').val();
});
