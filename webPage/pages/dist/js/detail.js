/**
 * Created by lenovo on 2018/7/19.
 */
$.getJSON ("/report/Background_PC/index.json", function (data) {
    $.each(data, function (i, item) {
        setTimeout(function() {
        $.getJSON(item, function (data) {
            $.each(data, function (i, item) {
                var info = item.info;
                var type = '';
                if(item.is_malicious===1){
                    type = "<span class=\"label label-danger\">恶意</span>";
                }else{
                    type = "<span class=\"label label-success\">良性</span>";
                }
                $("#results-display").append("<tr><td>" + item.srcIP +
                    "</td><td>" + item.srcPort +
                    "</td><td>" + item.dstIP +
                    "</td><td>" + item.dstPort +
                    "</td><td>" + item.time +
                    "</td><td>" + type + "</td></tr>");
            });
        });
        }, 1);
    });
    // $('#footable_3').footable();
});
// window.onload = function() {$('#footable_3').footable();}
// setTimeout(function() {
//   $('#footable_3').footable();
// }, 100 * 1000);