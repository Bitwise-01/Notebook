'use strict';

let isCreatingnote = false;

$(document).ready(() => {
    getnotes();
});

function createnote() {
    let topicId = document.getElementById('topic-id').innerHTML;
    let noteField = document.getElementById('new-note-name');
    let noteTitle = noteField.value;

    if (!noteTitle.trim() || isCreatingnote) {
        return;
    }

    isCreatingnote = true;

    $.ajax({
        type: 'POST',
        url: '/createnote',
        data: { topic_id: topicId, note_title: noteTitle }
    }).done(function(resp) {
        let respMsg = resp['resp'];
        let noteId = resp['note_id'];
        let dateCreated = resp['date_created'];

        if (noteId) {
            let $note = $('<div>', { class: 'note' });
            $note.attr('onclick', `location.href='/note?topic_id=${topicId}&note_id=${noteId}'`);

            let $noteTitle = $('<span>', { class: 'note-name' });
            let $noteDate = $('<span>', { class: 'note-date' });

            $noteTitle.append(noteTitle);
            $noteDate.append(dateCreated);

            $note.append($noteTitle);
            $note.append($noteDate);
            $('#notes').prepend($note);
        }

        if (noteField.classList.contains('error-msg')) {
            noteField.classList.remove('error-msg');
        }

        if (noteField.classList.contains('success-msg')) {
            noteField.classList.remove('success-msg');
        }

        if (respMsg == 'success-msg') {
            noteField.value = '';
        }

        noteField.focus();
        isCreatingnote = false;
        noteField.classList.add(respMsg);
    });
}

function getnotes() {
    let topicId = document.getElementById('topic-id').innerHTML;

    $.ajax({
        type: 'POST',
        url: '/getnotes',
        data: { topic_id: topicId }
    }).done(function(resp) {
        let note;
        let noteId;
        let noteTitle;
        let dateCreated;
        let notes = resp['notes'];

        let $note;
        let $noteDate;
        let $noteTitle;

        for (let n = 0; n < notes.length; n++) {
            note = notes[n];
            noteId = note['note_id'];
            noteTitle = note['note_title'];
            dateCreated = note['date_created'];

            $note = $('<div>', { class: 'note' });

            $note.attr('title', noteTitle);
            $note.attr('onclick', `location.href='/note?topic_id=${topicId}&note_id=${noteId}'`);

            $noteTitle = $('<span>', { class: 'note-name' });
            $noteDate = $('<span>', { class: 'note-date' });

            $noteTitle.append(noteTitle);
            $noteDate.append(dateCreated);

            $note.append($noteTitle);
            $note.append($noteDate);
            $('#notes').append($note);
        }
    });
}
