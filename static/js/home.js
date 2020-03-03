'use strict';

let isCreatingTopic = false;

$(document).ready(() => {
    getLastActive();
    getTopics();
});

function getLastActive() {
    let timestamp = $('#last-active-timestamp').val();
    let t = new Date(timestamp * 1000);
    let lastActive = null;

    try {
        lastActive = dateFormat(t, 'mmm dd, yyyy') + ' at ' + dateFormat(t, 'hh:MM TT');
        lastActive = $('<p>', { id: 'last-active' }).append('last accessed on ' + lastActive);
        $('#last-active').replaceWith(lastActive);
    } catch (e) {}
}

function createTopic() {
    let topicField = document.getElementById('new-topic-name');
    let topicName = topicField.value;

    if (!topicName.trim() || isCreatingTopic) {
        return;
    }

    isCreatingTopic = true;
    topicName = clean(topicName);

    $.ajax({
        type: 'POST',
        url: '/createtopic',
        data: { topic_name: topicName, time_stamp: new Date().getTime() },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(resp => {
        let respMsg = resp['resp'];
        let topicId = resp['topic_id'];

        if (topicId) {
            let timestamp = new Date(resp['date_created'] * 1000);
            let $topic = $('<tr>', { class: 'row', onclick: `location.href='/topic?id=${topicId}'` });

            $topic.append(
                $('<td>')
                    .css({ 'text-transform': 'capitalize' })
                    .append(topicName)
            );
            $topic.append($('<td>').append(dateFormat(timestamp, 'mmmm dd, yyyy')));
            $topic.append($('<td>').append(dateFormat(timestamp, 'dddd')));
            $topic.append($('<td>').append(dateFormat(timestamp, 'hh:MM:ss TT')));

            $('#topics tr:first').after($topic);
        }

        if (topicField.classList.contains('error-msg')) {
            topicField.classList.remove('error-msg');
        }

        if (topicField.classList.contains('success-msg')) {
            topicField.classList.remove('success-msg');
        }

        if (respMsg == 'success-msg') {
            topicField.value = '';
        }

        topicField.focus();
        isCreatingTopic = false;
        topicField.classList.add(respMsg);
    });
}

function getTopics() {
    $.ajax({
        type: 'POST',
        url: '/gettopics',
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(resp => {
        let $topic;
        let $tr = $('<tr>');
        let $table = $('<table>', { id: 'topics' });

        let topicId;
        let timestamp;
        let topicTitle;

        $tr.append($('<th>').append('Title'));
        $tr.append($('<th>').append('Date Created'));
        $tr.append($('<th>').append('Day Created'));
        $tr.append($('<th>').append('Time Created'));
        $table.append($tr);

        resp['topics'].forEach(topic => {
            topicId = topic['topic_id'];
            topicTitle = decodeEscaped(topic['topic_name']);
            timestamp = new Date(topic['date_created'] * 1000);

            $topic = $('<tr>', { class: 'row', onclick: `location.href='/topic?id=${topicId}'` });
            $topic.append(
                $('<td>')
                    .css({ 'text-transform': 'capitalize' })
                    .append(topicTitle)
            );
            $topic.append($('<td>').append(dateFormat(timestamp, 'mmmm dd, yyyy')));
            $topic.append($('<td>').append(dateFormat(timestamp, 'dddd')));
            $topic.append($('<td>').append(dateFormat(timestamp, 'hh:MM:ss TT')));

            $table.append($topic);
        });

        $('#table-container').append($table);
    });
}
