var roundDate = new Date();

document.addEventListener('DOMContentLoaded', function() {
    var dateOptions = {
        defaultDate: new Date(),
        setDefaultDate: true,
        minDate : new Date(),
        changeYear: true,
        changeMonth: true,
        onSelect : captureDate
    };

    var timeOptions = {
        twelveHour : false,
        onSelect : captureTime
    };
    
    var timeElems = document.querySelectorAll('.timepicker');
    timeInstances = M.Timepicker.init(timeElems, timeOptions);

    var dateElems = document.querySelectorAll('.datepicker');
    dateInstances = M.Datepicker.init(dateElems, dateOptions);

    $("#rounddiv").hide();
    $('input[type=radio]').on('click', function(e) {
        if (this.id == 'round') {
            $("#timediv").hide();
            $("#rounddiv").show();
        } else if (this.id == 'time') { 
            $("#timediv").show();
            $("#rounddiv").hide();
        }
    });

    $('#message').on('input', function(e) {
        var message = $("#message").val();
        if (message.length < 2){
            $("#encbutton").attr('disabled','disabled');
        }
        else {
            $("#encbutton").removeAttr('disabled');
        }
    });

    $('#enc').on('input', function(e) {
        var message = $("#enc").val();
        if (message.length < 20){
            $("#decbutton").attr('disabled','disabled');
        }
        else {
            $("#decbutton").removeAttr('disabled');
        }
    });
    
});

function captureTime(hours, minutes){
    roundDate.setHours(hours);
    roundDate.setMinutes(minutes);
}

function captureDate(date){
    roundDate.setDate(date.getDate());
    roundDate.setMonth(date.getMonth());
    roundDate.setFullYear(date.getFullYear());
}

function encrypt(){
    var round, timeBool;

    if ($('input[type=radio][id=round]').prop('checked')){
        round = $("#roundno").val();
        timeBool = false;
    }
    else {
        round = roundDate.getTime();
        timeBool = true;
    }
    var message = $("#message").val();

    $.post("encrypt", {round: round, message: message , timeBool : timeBool}, function(result){
        $("#encresult").text(result.enc);
    });
}

function decrypt(){
    var enc = $("#enc").val();
    $.post("decrypt", {enc: enc}, function(result){
        $("#decresult").text(result.message);
    });
}

function current(){
    $.get("current" , function(data){
        $("#encresult").text( "The current round is " + data.round);
    })
}

