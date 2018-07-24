/**
 * Created by lenovo on 2018/7/23.
 */
$(function() {
    $.getJSON("/report/export.json", function (data) {
        $.each(data, function (i, item) {
            $("#results-display").append("<tr><td>" + item.srcIP +
                "</td><td>" + item.srcPort +
                "</td><td>" + item.dstIP +
                "</td><td>" + item.dstPort +
                "</td><td>" + item.UA +
                "</td><td>" + item.time + "</td></tr>");
        });
        }
    });
});
