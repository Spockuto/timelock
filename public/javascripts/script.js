document.addEventListener('DOMContentLoaded', function() {
    var elems = document.querySelectorAll('.timepicker');
    var instances = M.Timepicker.init(elems);

    var elems = document.querySelectorAll('.datepicker');
    var instances = M.Datepicker.init(elems);

    $("#timediv").hide();
    $('input[type=radio]').on('click', function(e) {
        if (this.id == 'round') {
            $("#timediv").hide();
            $("#rounddiv").show();
        } else if (this.id == 'time') { 
            $("#timediv").show();
            $("#rounddiv").hide();
        }
      });
    
});
