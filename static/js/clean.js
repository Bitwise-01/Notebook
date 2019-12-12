'use strict';

function clean(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/"/g, '&quot;');
}

function decodeEscaped(str) {
    let textArea = document.createElement('textarea');
    textArea.innerHTML = str;
    return textArea.value;
}
