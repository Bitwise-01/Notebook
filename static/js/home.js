'use strict';

let isCreatingTopic = false;

$(document).ready(() => {
    getTopics();
});

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
        data: { topic_name: topicName },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(function(resp) {
        let respMsg = resp['resp'];
        let topicId = resp['topic_id'];
        let dateCreated = resp['date_created'];

        if (topicId) {
            let $topic = $('<div>', { class: 'topic' });

            $topic.attr('title', topicName);
            $topic.attr('onclick', `location.href='/topic?id=${topicId}'`);

            let $topicName = $('<span>', { class: 'topic-name' });
            let $topicDate = $('<span>', { class: 'topic-date' });

            $topicName.append(topicName);
            $topicDate.append(dateCreated);

            $topic.append($topicName);
            $topic.append($topicDate);
            $('#topics').prepend($topic);
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
    }).done(function(resp) {
        let topic;
        let topicId;
        let topicName;
        let dateCreated;
        let topics = resp['topics'];

        let $topic;
        let $topicName;
        let $topicDate;

        for (let n = 0; n < topics.length; n++) {
            topic = topics[n];
            topicId = topic['topic_id'];
            topicName = topic['topic_name'];
            dateCreated = topic['date_created'];

            $topic = $('<div>', { class: 'topic' });

            $topic.attr('title', topicName);
            $topic.attr('onclick', `location.href='/topic?id=${topicId}'`);

            $topicName = $('<span>', { class: 'topic-name' });
            $topicDate = $('<span>', { class: 'topic-date' });

            $topicName.append(topicName);
            $topicDate.append(dateCreated);

            $topic.append($topicName);
            $topic.append($topicDate);
            $('#topics').append($topic);
        }
    });
}
