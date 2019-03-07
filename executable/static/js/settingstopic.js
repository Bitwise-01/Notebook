'use strict';

let isPrompt = false;
let lastTopicName = null;
let isUpdatingName = false;

function updateName() {
    let topicName = $('#topic-name');
    let newNameInput = $('#new-topic-name');

    if (!lastTopicName) {
        newNameInput.val(topicName.text());
        newNameInput.removeAttr('disabled');
    
        lastTopicName = topicName.text();
        $('#update-topic').text('Update');

    } else {
        if ((newNameInput.val() != lastTopicName) && !isUpdatingName) {
            isUpdatingName = true;
            update(newNameInput.val());
        }
    }
}

function update(newName) {
    if (!newName.length) {
        return;
    }

    let topicId = $('#topic-id').text();
    let newNameInput = $('#new-topic-name');

    $.ajax({
        type: 'POST',
        url: '/settings/topic/update',
        data: { 'topic_id': topicId, 'modified_name': newName }
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
            newNameInput.attr('placeholder', newName);
        }
        
        isUpdatingName = false;
        newNameInput.addClass(respMsg);
    });
}

function deleteTopic(code) {
    let overlay = $('#overlay');
    let topicId = $('#topic-id').text();

    overlay.css({'display': (isPrompt ? 'none' : 'block')}); 
    $('html').css({'overflow': isPrompt ? 'auto' : 'hidden'});
    $('body').css({'overflow': isPrompt ? 'auto' : 'hidden'});
    isPrompt = !isPrompt;

    if (code == 1) {
        $.ajax({
            type: 'POST',
            url: '/settings/topic/delete',
            data: { 'topic_id': topicId }
        }).done(function(resp) {
            let respMsg = resp['resp'];
                            
            if (respMsg == 'success-msg') {
                window.location.href = '/';
            }
        });
    }
}