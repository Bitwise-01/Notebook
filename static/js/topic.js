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
    noteTitle = clean(noteTitle);

    $.ajax({
        type: 'POST',
        url: '/createnote',
        data: { topic_id: topicId, note_title: noteTitle, time_stamp: new Date().getTime() },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(resp => {
        let respMsg = resp['resp'];
        let noteId = resp['note_id'];

        if (noteId) {
            let timestamp = new Date(resp['date_created'] * 1000);
            let $note = $('<tr>', {
                class: 'row',
                onclick: `location.href='/note?topic_id=${topicId}&note_id=${noteId}'`
            });

            $note.append(
                $('<td>')
                    .css({ 'text-transform': 'capitalize' })
                    .append(noteTitle)
            );
            $note.append($('<td>').append(dateFormat(timestamp, 'mmmm dd, yyyy')));
            $note.append($('<td>').append(dateFormat(timestamp, 'dddd')));
            $note.append($('<td>').append(dateFormat(timestamp, 'hh:MM:ss TT')));

            $('#notes tr:first').after($note);
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
        data: { topic_id: topicId },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(resp => {
        let noteId;
        let timestamp;

        let $note;
        let $tr = $('<tr>');
        let $table = $('<table>', { id: 'notes' });

        $tr.append($('<th>').append('Title'));
        $tr.append($('<th>').append('Date Created'));
        $tr.append($('<th>').append('Day Created'));
        $tr.append($('<th>').append('Time Created'));
        $table.append($tr);

        resp['notes'].forEach(note => {
            noteId = note['note_id'];
            timestamp = new Date(note['date_created'] * 1000);

            $note = $('<tr>', {
                class: 'row',
                onclick: `location.href='/note?topic_id=${topicId}&note_id=${noteId}'`
            });
            $note.css({ 'text-transform': 'capitalize' }).append($('<td>').append(note['note_title']));
            $note.append($('<td>').append(dateFormat(timestamp, 'mmmm dd, yyyy')));
            $note.append($('<td>').append(dateFormat(timestamp, 'dddd')));
            $note.append($('<td>').append(dateFormat(timestamp, 'hh:MM:ss TT')));

            $table.append($note);
        });

        $('#table-container').append($table);
    });
}
