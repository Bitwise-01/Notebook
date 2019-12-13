'use strict';

const countDownDefault = 5;
const saveError = 'Failed to save note';
const textEditor = document.getElementById('editor');

let lastSaved = null;
let initHtmlHash = null;
let lastHtmlHash = null;

let isSaved = true;
let isPrompt = false;
let autoSaved = false;
let isDisplayed = false;
let isModifyingName = false;

let countDown = countDownDefault;

$(document).ready(() => {
    keypress();
    renderFonts();
    setInterval(activeSave, 1000);

    document.getElementById('font-size').selectedIndex = 2;
    sha256(document.getElementById('editor').innerHTML.trim()).then(r => {
        initHtmlHash = r;
    });
});

async function activeSave() {
    if (countDown > 0) {
        countDown--;
    } else {
        await save();
        countDown = countDownDefault;
    }
}

function execute(cmd, value) {
    document.execCommand(cmd, false, value);
    textEditor.focus();
}

function renderFonts() {
    let fontsTag = document.getElementById('fonts');

    for (let n = 0; n < fontsTag.length; n++) {
        fontsTag[n].style.fontFamily = fontsTag[n].value;
    }

    let initFont = fontsTag.length - 1;

    textEditor.style.fontFamily = fontsTag[initFont].value;
    document.getElementById('fonts').selectedIndex = initFont;
}

function keypress() {
    document.addEventListener('keydown', e => {
        countDown = countDownDefault;

        if ((e.ctrlKey || e.metaKey) && String.fromCharCode(e.which).toLowerCase() == 's') {
            e.preventDefault();
            save(false);
        }

        if (e.shiftKey && e.keyCode == 9) {
            execute('outdent');
            return;
        }

        if (!e.shiftKey && e.keyCode == 9) {
            e.preventDefault();
            execute('indent');
        }
    });
}

async function save(autoSave = true) {
    let noteId = $('#note-id').text();
    let topicId = $('#topic-id').text();
    let timeDisplay = $('#time-display');

    let htmlHash = null;
    let html = document.getElementById('editor').innerHTML.trim();

    await sha256(html).then(r => {
        htmlHash = r;
    });

    if (!isSaved) {
        if (!timeDisplay.text()) {
            timeDisplay.innerHTML = saveError;
        }

        return;
    }

    if (!autoSave && isDisplayed) {
        modify();
    }

    if (autoSave && html.length == 0) {
        return;
    }

    if (initHtmlHash == htmlHash) {
        return;
    }

    if (initHtmlHash) {
        initHtmlHash = null;
    }

    if (htmlHash == lastHtmlHash) {
        let diff = Math.round((new Date().getTime() - lastSaved.getTime()) / 1000);

        if (diff <= 15) {
            timeDisplay.text(autoSaved ? `Auto saved ${diff} seconds ago` : `Saved ${diff} seconds ago`);
        } else if (diff >= 60) {
            let time = lastSaved.toLocaleTimeString();
            time = time.slice(0, time.match(/\s/).index);
            timeDisplay.text(autoSaved ? `Auto saved at ${time}` : `Saved at ${time}`);
        } else {
            timeDisplay.text('');
        }

        return;
    }

    $.ajax({
        type: 'POST',
        url: '/save',
        data: { topic_id: topicId, note_id: noteId, content: html },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(function(resp) {
        let respMsg = resp['resp'];

        if (respMsg != 'success-msg') {
            isSaved = false;
            timeDisplay.innerHTML = saveError;
            return;
        }

        timeDisplay.text(autoSave ? 'Auto saved now' : 'Saved now');
        lastSaved = new Date();

        if (autoSave) {
            autoSaved = true;
        } else {
            autoSaved = false;
        }

        lastHtmlHash = htmlHash;
        countDown = countDownDefault;
    });
}

function modify() {
    let nameInput = $('#name');

    if (!isDisplayed) {
        isDisplayed = true;
        $('#modify').text('Update Title');
        nameInput.css({ opacity: 1, visibility: 'visible' });
    } else {
        if (!isModifyingName) {
            modifyName(nameInput);
        }
    }
}

function modifyName(nameInput) {
    isModifyingName = true;
    let name = clean(nameInput.val());
    let noteId = $('#note-id').text();
    let topicId = $('#topic-id').text();

    $.ajax({
        type: 'POST',
        url: '/modify',
        data: { topic_id: topicId, note_id: noteId, modified_title: name },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(function(resp) {
        let respMsg = resp['resp'];

        if (nameInput.hasClass('error-msg')) {
            nameInput.removeClass('error-msg');
        }

        if (respMsg == 'success-msg') {
            nameInput.val('');
            nameInput.attr('placeholder', name);

            isDisplayed = false;
            $('#modify').text('Change Title');
            $('#note-title').text(name);
            nameInput.css({ opacity: 0, visibility: 'hidden' });
        } else {
            nameInput.addClass(respMsg);
        }

        isModifyingName = false;
    });
}

function deleteNote(code) {
    let overlay = $('#overlay');
    let noteId = $('#note-id').text();
    let topicId = $('#topic-id').text();

    overlay.css({ display: isPrompt ? 'none' : 'block' });
    $('html').css({ overflow: isPrompt ? 'auto' : 'hidden' });
    $('body').css({ overflow: isPrompt ? 'auto' : 'hidden' });
    isPrompt = !isPrompt;

    if (code == 1) {
        $.ajax({
            type: 'POST',
            url: '/delete',
            data: { topic_id: topicId, note_id: noteId },
            beforeSend: function(request) {
                request.setRequestHeader('X-CSRFToken', CSRFToken);
            }
        }).done(function(resp) {
            let respMsg = resp['resp'];

            if (respMsg == 'success-msg') {
                window.location.href = `/topic?id=${topicId}`;
            }
        });
    }
}

async function sha256(str) {
    const min = 0;
    const max = 16;

    // encode as UTF-8
    const msgBuffer = new TextEncoder('utf-8').encode(str);

    // hash the str
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

    // convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // convert bytes to hex string
    const hashHex = hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('');

    const a = hashHex.slice(min, max);
    const b = hashHex.slice(-max);
    const c = hashHex.slice(max, max * 2);

    const d = c.slice(c.length / 2);
    const e = b.slice(0, b.length / 2);
    const f = a.slice(0, a.length / 2);
    const g = a.slice(a.length / 2);

    return g + d + f + e;
}
