


$(document).ready(function() {
    $('#schedule-form').on('submit', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr('action'),
            method: $(this).attr('method'),
            data: $(this).serialize(),
            success: function(response) {
                $('#flash-messages').html('');
                if (response.status === 'error') {
                    $('#flash-messages').append('<div class="alert alert-danger" role="alert">' + response.message + '</div>');
                    // Highlight the conflicting fields
                    $('input[name="start_time"]').addClass('is-invalid');
                    $('input[name="end_time"]').addClass('is-invalid');
                } else {
                    $('#flash-messages').append('<div class="alert alert-success" role="alert">' + response.message + '</div>');
                    setTimeout(function() {
                        location.reload();
                    }, 2000);
                }
            }
        });
    });

    $('.edit-schedule-form').on('submit', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr('action'),
            method: $(this).attr('method'),
            data: $(this).serialize(),
            success: function(response) {
                $('#flash-messages').html('');
                if (response.status === 'error') {
                    $('#flash-messages').append('<div class="alert alert-danger" role="alert">' + response.message + '</div>');
                    // Highlight the conflicting fields
                    $('input[name="start_time"]').addClass('is-invalid');
                    $('input[name="end_time"]').addClass('is-invalid');
                } else {
                    $('#flash-messages').append('<div class="alert alert-success" role="alert">' + response.message + '</div>');
                    setTimeout(function() {
                        location.reload();
                    }, 2000);
                }
            }
        });
    });
});