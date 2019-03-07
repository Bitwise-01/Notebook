'use strict';

$(document).ready(() => {
    $('#menu-container').click(() => {
        let navbar = document.getElementById('navbar');
        
        if (!(navbar.classList.contains('show') || navbar.classList.contains('hide'))) {
            navbar.classList.add('show');
        } else {
            if (navbar.classList.contains('show')) {
                navbar.classList.remove('show');
                navbar.classList.add('hide');
            } else {
                navbar.classList.remove('hide');
                navbar.classList.add('show');
            }
        }
    })
});

$('#container').click(() => {
    if (navbar.classList.contains('show')) {
        navbar.classList.remove('show');
        navbar.classList.add('hide');
    } 
});