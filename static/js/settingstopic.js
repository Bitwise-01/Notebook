'use strict';

let isPrompt = false;
let isUpdatingName = false;

function update() {
    let newName = $('#new-topic-name').val();

    if (!newName.length) {
        return;
    }

    newName = clean(newName);
    let respText = $('#resp');
    let topicId = $('#topic-id').text();
    let newNameInput = $('#new-topic-name');

    if (isUpdatingName) {
        return;
    }

    $.ajax({
        type: 'POST',
        url: '/settings/topic/update',
        data: { topic_id: topicId, modified_name: newName },
        beforeSend: function(request) {
            request.setRequestHeader('X-CSRFToken', CSRFToken);
        }
    }).done(function(resp) {
        let respMsg = resp['resp'];

        if (newNameInput.hasClass('error-msg')) {
            newNameInput.removeClass('error-msg');
        }

        if (newNameInput.hasClass('success-msg')) {
            newNameInput.removeClass('success-msg');
        }

        if (respMsg == 'success-msg') {
            newNameInput.val('');
            respText.text('Name Updated Successfully');
        } else {
            respText.text('');
        }

        isUpdatingName = false;
        newNameInput.addClass(respMsg);
    });
}

function deleteTopic(code) {
    let overlay = $('#overlay');
    let topicId = $('#topic-id').text();

    overlay.css({ display: isPrompt ? 'none' : 'block' });
    $('html').css({ overflow: isPrompt ? 'auto' : 'hidden' });
    $('body').css({ overflow: isPrompt ? 'auto' : 'hidden' });
    isPrompt = !isPrompt;

    if (code == 1) {
        $.ajax({
            type: 'POST',
            url: '/settings/topic/delete',
            data: { topic_id: topicId },
            beforeSend: function(request) {
                request.setRequestHeader('X-CSRFToken', CSRFToken);
            }
        }).done(function(resp) {
            let respMsg = resp['resp'];

            if (respMsg == 'success-msg') {
                window.location.href = '/';
            }
        });
    }
}
