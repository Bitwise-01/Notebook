'use strict';

let isSaved = true;
let initHtml = null;
let lastHtml = null;
let isPrompt = false;
let isActive = false;
let lastSaved = null;
let autoSaved = false;
let isDisplayed = false;
let isModifyingName = false;
const autoSaveDelay = 15 * 1000; // 15 * 1000 => 15(sec)
const saveError = 'Failed to save note';
const textEditor = document.getElementById('editor');

$(document).ready(() => {
    keypress();
    renderFonts();
    setInterval(save, autoSaveDelay);
    document.getElementById('font-size').selectedIndex = 2;
    initHtml = document.getElementById('editor').innerHTML.trim();
});

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
        isActive = true;

        if ((e.ctrlKey || e.metaKey) && String.fromCharCode(e.which).toLowerCase() == 's') {
            e.preventDefault();
            save(false);
        }

        if (e.shiftKey && e.keyCode == 9) {
            execute('outdent');
            isActive = false;
            return;
        }

        if (!e.shiftKey && e.keyCode == 9) {
            e.preventDefault();
            execute('indent');
        }

        isActive = false;
    });
}

function save(autoSave = true) {
    let noteId = $('#note-id').text();
    let topicId = $('#topic-id').text();
    let timeDisplay = $('#time-display');
    let html = document.getElementById('editor').innerHTML.trim();

    if (!isSaved) {
        if (!timeDisplay.text()) {
            timeDisplay.innerHTML = saveError;
        }

        return;
    }

    if (!autoSave && isDisplayed) {
        modify();
    }

    if (autoSave && !html.length) {
        return;
    }

    if (initHtml == html) {
        return;
    }

    if (initHtml) {
        initHtml = null;
    }

    if (html == lastHtml) {
        let diff = Math.round((new Date().getTime() - lastSaved.getTime()) / 1000);

        if (diff < 60) {
            timeDisplay.text(autoSaved ? `Auto saved ${diff} seconds ago` : `Saved ${diff} seconds ago`);
        } else {
            let time = lastSaved.toLocaleTimeString();
            timeDisplay.text(autoSaved ? `Auto saved at ${time}` : `Saved at ${time}`);
        }

        return;
    }

    if (autoSave && isActive) {
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

        lastHtml = html;
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
